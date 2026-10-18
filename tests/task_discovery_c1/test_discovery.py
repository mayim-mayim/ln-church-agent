"""A3/A4/A7 SDK self-check against audited c1, with isolated transport only."""
import base64
import copy
import json
import sys
import traceback

import pytest
from pydantic import ValidationError

from ln_church_agent import AgentTaskClient, TaskDiscoveryCandidate, TaskDiscoveryPage
from ln_church_agent.access_quota import AccessQuotaError, AccessQuotaPolicy
from ln_church_agent.task_models import AgentTaskPage
from ln_church_agent.task_transport import TaskTransport, TaskError, TaskTransportError
from discovery_fixtures import ORIGIN, ROWS, candidate, cursor, page


class Exchange:
    """Real SDK transport; synthetic DNS, clock and HTTP boundary."""
    def __init__(self, payload=None, status=200, error=None, policy=None):
        self.payload=page() if payload is None else payload
        self.status=status; self.error=error; self.calls=[]
        self.transport=TaskTransport(
            _resolver=lambda *_:['8.8.8.8'], _exchange=self.send,
            _sleep=lambda _:pytest.fail('Discovery must not retry or sleep'),
            access_quota=policy)
        self.client=AgentTaskClient(_transport=self.transport)

    def send(self, **kw):
        self.calls.append(kw)
        if self.error is not None:raise self.error
        return self.status,{'content-type':'application/json'},json.dumps(self.payload).encode()


@pytest.mark.parametrize('index',range(12),ids=[r[0]+'/'+r[1] for r in ROWS])
def test_each_official_tuple_is_read_without_selector_or_hydration(index):
    wire=page((index,))
    ex=Exchange(wire)
    result=ex.client.discover_tasks(limit=1)
    assert type(result) is TaskDiscoveryPage
    assert type(result.tasks[0]) is TaskDiscoveryCandidate
    assert result.model_dump(mode='json')==wire
    assert len(ex.calls)==1
    call=ex.calls[0]
    assert call['method']=='GET' and call['url']==ORIGIN+'/api/agent/tasks'
    assert call['params']=={'limit':1} and call['body'] is None and call['claim_token'] is None


def test_default_mixed_page_retains_tuples_capacity_and_links_without_claim():
    wire=page(tuple(range(12)),more=True)
    ex=Exchange(wire)
    result=ex.client.discover_tasks()
    assert ex.calls[0]['params']=={'limit':20}
    assert result.model_dump(mode='json')==wire
    assert len(ex.calls)==1 and len(result.tasks)==12
    scheduled=result.tasks[1]
    assert scheduled.scheduled_at!=scheduled.claim_before
    assert result.tasks[9].task_definition_version=='2.0.0'
    assert result.tasks[10].task_schema_version.endswith('.v2_1')


@pytest.mark.parametrize('continuation,more',[(False,False),(False,True),(True,False),(True,True)])
def test_empty_range_and_continuation_are_independent(continuation,more):
    wire=page((),continuation=continuation,more=more)
    previous=cursor(after='2026-10-23T07:30:00.000Z#task_old') if continuation else None
    ex=Exchange(wire)
    result=ex.client.discover_tasks(cursor=previous)
    assert result.tasks==[]
    assert result.page_scope==('continuation' if continuation else 'initial')
    assert result.empty_reason=='no_candidates_observed_in_range'
    assert result.next_cursor==wire['next_cursor']
    assert ex.calls[0]['params']==dict(limit=20,**({'cursor':previous} if previous else {}))


def test_explicit_next_page_and_fresh_search_do_not_reuse_cursor():
    ex=Exchange(page(more=True))
    first=ex.client.discover_tasks()
    ex.payload=page((),continuation=True)
    second=ex.client.discover_tasks(cursor=first.next_cursor)
    ex.payload=page((10,))
    fresh=ex.client.discover_tasks()
    assert second.page_scope=='continuation' and fresh.tasks[0].task_definition_version=='2.1.0'
    assert [c['params'] for c in ex.calls]==[
        {'limit':20},{'limit':20,'cursor':first.next_cursor},{'limit':20}]


@pytest.mark.parametrize('limit',[True,False,0,51,-1,'20',20.0,None])
def test_bad_limit_is_local_error_before_network(limit):
    ex=Exchange()
    with pytest.raises(TaskError) as caught:ex.client.discover_tasks(limit=limit)
    assert caught.value.request_bytes_sent is False and ex.calls==[]


@pytest.mark.parametrize('value',['','legacy-list-cursor','iv3.old','td1.','td1.@@@@',
    'td1.'+'a'*1021,'td1.'+base64.urlsafe_b64encode(b'{}').decode().rstrip('='),
    cursor(after='not-a-date#task_1'),cursor(after='2026-10-24T07:30:00.000Z#bad/id')])
def test_old_other_family_or_invalid_cursor_never_becomes_first_page(value):
    ex=Exchange()
    with pytest.raises(TaskError) as caught:ex.client.discover_tasks(cursor=value)
    assert caught.value.request_bytes_sent is False and ex.calls==[]


@pytest.mark.parametrize('change',[
    {'schema_version':'ln_church.agent_task_page.v1'},
    {'coverage':'unavailable'},{'page_scope':'other'},
    {'claim_authority':'sdk'},{'selection':'all_tasks'},
    {'empty_reason':'no_candidates_observed_in_range'},
    {'next_cursor':'legacy-cursor'},{'checked_at':'invalid'},
])
def test_invalid_envelope_is_an_error_not_success_zero(change):
    wire=page();wire.update(change);ex=Exchange(wire)
    with pytest.raises(TaskError):ex.client.discover_tasks()
    assert len(ex.calls)==1


@pytest.mark.parametrize('key',list(page()))
def test_required_page_fields_have_no_success_defaults(key):
    wire=page();wire.pop(key)
    with pytest.raises(ValidationError):TaskDiscoveryPage.model_validate(wire)


@pytest.mark.parametrize('change',[
    {'task_schema_version':'ln_church.agent_task.endpoint_choice_reason.v2'},
    {'task_definition_version':'2.0.0'}, {'task_type':'unknown.v1'},
    {'task_definition_digest':'not-a-digest'},{'capacity_available':0},
    {'capacity_available':True},{'capacity_available':'3'},
    {'recruitment_state':'claimable'},{'eligibility':'guaranteed'},
    {'scheduled_at':'2026-10-24T08:00:00.000Z'}, {'claim_before':'invalid'},
    {'projection_updated_at':None},
    {'detail_url':ORIGIN+'/api/agent/tasks/different'},
    {'detail_url':'https://other.example/api/agent/tasks/task_11'},
    {'definition_url':ORIGIN+'/agent-task-specs/structured_response.v3/2.0.0/SKILL.md'},
])
def test_bad_tuple_or_observation_is_not_silently_dropped(change):
    wire=page();wire['tasks'][0].update(change);ex=Exchange(wire)
    with pytest.raises(TaskError):ex.client.discover_tasks()
    assert len(ex.calls)==1


def test_link_selector_crossing_duplicates_extra_private_pointer_and_schedule_rejected():
    for suffix in ('&task_schema_version=wrong','&private_pointer=internal',
                   '&task_type=structured_response.v3','#private'):
        wire=page();wire['tasks'][0]['detail_url']+=suffix
        with pytest.raises(TaskError):Exchange(wire).client.discover_tasks()
    wire=page((1,));wire['tasks'][0]['scheduled_at']=None
    with pytest.raises(TaskError):Exchange(wire).client.discover_tasks()


def test_text_utf8_bounds_are_checked_without_sdk_truncation_or_digest_rewrite():
    wire=page();wire['tasks'][0].update(title='é'*128,summary='😀'*64)
    assert Exchange(wire).client.discover_tasks().tasks[0].title=='é'*128
    wire['tasks'][0]['title']+='é'
    with pytest.raises(TaskError):Exchange(wire).client.discover_tasks()


@pytest.mark.parametrize('status',[400,503,402])
def test_http_failure_retains_status_never_becomes_empty_or_retries(status):
    ex=Exchange(dict(schema_version='ln_church.task_discovery_error.v1',
        code='invalid_cursor' if status==400 else 'discovery_unavailable',
        coverage='unavailable',message='PRIVATE_BODY_MARKER',request_id='synthetic'),status)
    with pytest.raises(TaskError) as caught:ex.client.discover_tasks()
    assert caught.value.status_code==status and len(ex.calls)==1
    assert 'PRIVATE_BODY_MARKER' not in repr(vars(caught.value))
    assert caught.value.__context__ is None


def test_unreachable_transport_is_not_empty_and_does_not_retry():
    ex=Exchange(error=TimeoutError('PRIVATE_BODY_MARKER'))
    with pytest.raises(TaskError) as caught:ex.client.discover_tasks()
    assert len(ex.calls)==1 and caught.value.code=='TASK_TIMEOUT'
    assert 'PRIVATE_BODY_MARKER' not in ''.join(traceback.format_exception(caught.type,caught.value,caught.tb))


def test_private_meta_is_not_retained_in_page_candidate_or_repr():
    wire=page();wire['raw_meta']={'target':'PRIVATE_BODY_MARKER'}
    wire['tasks'][0].update(private_pointer='PRIVATE_BODY_MARKER',
        correct_answer='PRIVATE_BODY_MARKER',terms={'order_id':'PRIVATE_BODY_MARKER'})
    model=Exchange(wire).client.discover_tasks()
    assert 'PRIVATE_BODY_MARKER' not in model.model_dump_json()
    assert 'PRIVATE_BODY_MARKER' not in repr(model)


def test_bad_page_cannot_leak_unknown_private_input_in_exception_graph():
    wire=page();wire['tasks'][0]['capacity_available']=False
    wire['raw_meta']='PRIVATE_BODY_MARKER';ex=Exchange(wire)
    with pytest.raises(TaskError) as caught:ex.client.discover_tasks()
    err=caught.value
    assert err.__cause__ is None and err.__context__ is None
    assert 'PRIVATE_BODY_MARKER' not in str(err)+repr(vars(err))+''.join(traceback.format_exception(type(err),err,err.__traceback__))


def test_scope_length_and_nonadvancing_cursor_mismatch_are_errors():
    for wire,kwargs in [
        (page(continuation=True),{}),
        (page((10,11)),{'limit':1}),
        (page(more=True),{'cursor':cursor()}),
        (page((),continuation=True,more=True),{'cursor':cursor()}),
    ]:
        with pytest.raises(TaskError):Exchange(wire).client.discover_tasks(**kwargs)
    wire=page((),continuation=True);wire['empty_reason']=None
    with pytest.raises(TaskError):Exchange(wire).client.discover_tasks(cursor=cursor())


def test_existing_list_still_sends_legacy_selector_and_returns_legacy_model():
    legacy=dict(schema_version='ln_church.agent_task_page.v1',tasks=[],next_cursor='opaque_old')
    ex=Exchange(legacy)
    model=ex.client.list_tasks(cursor='previous_old')
    assert type(model) is AgentTaskPage
    assert model.next_cursor=='opaque_old'
    assert ex.calls[0]['params']==dict(task_type='payment_surface_discovery.v1',status='OPEN',limit=20,cursor='previous_old')
    ex.payload=page()
    with pytest.raises(TaskError):ex.client.discover_tasks(cursor='opaque_old')


def test_closed_client_and_origin_override_keep_existing_protection():
    ex=Exchange();ex.client.close()
    with pytest.raises(TaskError):ex.client.discover_tasks()
    assert ex.calls==[]
    with pytest.raises(TaskError):AgentTaskClient(api_origin='https://other.example')


def test_new_cursor_on_legacy_operation_keeps_selector_and_surfaces_server_rejection():
    ex=Exchange(dict(schema_version='ln_church.agent_task_error.v1',
        error_code='invalid_request',message='Synthetic old-cursor rejection'),400)
    with pytest.raises(TaskError):ex.client.list_tasks(cursor=cursor())
    assert len(ex.calls)==1
    assert ex.calls[0]['params']['task_type']=='payment_surface_discovery.v1'
    assert ex.calls[0]['params']['cursor']==cursor()


@pytest.mark.parametrize('target,extra', [('candidate',4000),('page',165000)])
def test_oversized_object_is_failure_instead_of_a_filtered_empty_page(target,extra):
    wire=page()
    if target=='candidate':wire['tasks'][0]['unexpected_private_meta']='x'*extra
    else:wire['unexpected_private_meta']='x'*extra
    with pytest.raises(TaskError):Exchange(wire).client.discover_tasks()


def test_real_quota_challenge_is_one_edge_call_zero_origin_or_purchase():
    # Existing authoritative challenge builder is synthetic and makes no I/O.
    from test_access_quota import challenge,NOW
    policy=AccessQuotaPolicy(wall_time=lambda:NOW)
    ex=Exchange(policy=policy)
    def quota(**kw):
        ex.calls.append(kw)
        from urllib.parse import urlencode
        url=kw['url']+'?'+urlencode(kw['params'])
        return challenge('GET',url,{},b'')
    ex.transport._exchange=quota
    with pytest.raises(AccessQuotaError) as caught:ex.client.discover_tasks()
    assert caught.value.code=='ACCESS_REQUIRED' and caught.value.origin_not_sent is True
    assert len(ex.calls)==1 and not ex.calls[0].get('access_headers')

