"""Role-UA adapter checks with explicitly non-normative synthetic pack data."""
import json
import pytest
from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
from ln_church_agent.immediate_visit_models import ImmediateVisitClaimCredential, ImmediateVisitTaskPage, FrozenImmediateVisitReport
from ln_church_agent.immediate_visit_transport import ImmediateVisitTransport, ImmediateVisitAPIError
from ln_church_agent.immediate_visit_journal import ImmediateVisitJournal
from ln_church_agent.immediate_visit import ImmediateVisitExecutor
from ln_church_agent import immediate_visit_versions as v
from test_v1_18_3_immediate_visit_client import Exchange,raw
from test_v1_18_3_immediate_visit_contract import task_wire,claim_wire,report_wire,TASK,ADDRESS,ENDPOINT
from test_v1_18_3_immediate_visit_transport import Harness
from test_v1_18_3_immediate_visit_contract import status_wire, EXECUTION

UA='ExternalAgent-via-LNChurch/1.0 (+https://kari.mayim-mayim.com/agent-offer-register.html#instant-site-visits)'
REF='LNChurch-Reference/1.0 (+https://kari.mayim-mayim.com/agent-offer-register.html#instant-site-visits)'

def v2(value):
    return json.loads(json.dumps(value).replace('immediate_visit.v1','immediate_visit.v2').replace('immediate_visit_utf8.v1','immediate_visit_utf8.v2').replace('immediate_http_visit.v1','immediate_http_visit.v2').replace('1.0.0','2.0.0'))

@pytest.fixture
def synthetic_pack(monkeypatch):
    monkeypatch.setattr(v,'load_v2_pack',lambda:{'profile.json':json.dumps(dict(profile_id='immediate_visit_utf8.v2',task_type='immediate_http_visit.v2',request_headers={'Accept':'*/*','Accept-Encoding':'identity'},user_agents={'agent':UA,'reference':REF})).encode()})


def test_default_v2_and_explicit_v1_discovery_are_separate():
    for version in ['v1','v2']:
        value=task_wire() if version=='v1' else v2(task_wire())
        ex=Exchange([raw(dict(schema_version='ln_church.agent_task_page.immediate_visit.'+version,tasks=[value],next_cursor=None))])
        client=AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=ex),**({'version':'v1'} if version=='v1' else {}))
        assert client.list_tasks().tasks[0].task_type=='immediate_http_visit.'+version
        assert 'task_type=immediate_http_visit.'+version in ex.requests[0][2]


def test_v2_dedicated_claim_has_no_preceding_detail_get(synthetic_pack):
    ex=Exchange([raw(v2(claim_wire()))])
    cli=AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=ex))
    result=cli.claim_task(TASK,'agent',ADDRESS,idempotency_key='key')
    assert len(ex.requests)==1 and ex.requests[0][0]=='POST'
    assert json.loads(ex.requests[0][4])['schema_version']=='ln_church.agent_task_claim_request.immediate_visit.v2'
    assert result.profile_id=='immediate_visit_utf8.v2'


def test_unsupported_old_claim_is_definite_rejection_without_fallback():
    ex=Exchange([raw(dict(schema_version='ln_church.task_error.immediate_visit.v1',code='unsupported_task_profile',message='no',request_id='r'),400)])
    cli=AgentImmediateVisitClient(version='v1',transport=ImmediateVisitTransport(exchange=ex))
    with pytest.raises(ImmediateVisitAPIError) as caught:cli.claim_task(TASK,'agent',ADDRESS,idempotency_key='key')
    assert caught.value.public_error_code=='unsupported_task_profile' and len(ex.requests)==1


def test_cross_tuple_and_mixed_page_rejected():
    value=v2(claim_wire());value['profile_id']='immediate_visit_utf8.v1'
    with pytest.raises(ValueError):ImmediateVisitClaimCredential.model_validate(value)
    with pytest.raises(ValueError):ImmediateVisitTaskPage.model_validate(dict(schema_version='ln_church.agent_task_page.immediate_visit.v2',tasks=[task_wire()],next_cursor=None))


def test_missing_pack_or_unknown_profile_stops_before_dns(monkeypatch):
    monkeypatch.setattr(v, "V2_PACK_SHA256", {})
    h=Harness()
    for profile in ['immediate_visit_utf8.v2','unknown']:
        with pytest.raises(ValueError):h.connector.fetch_immediate_visit('https://example.com/a',profile_id=profile)
    assert h.dns==[] and h.sockets==[]


def test_v2_actual_connector_request_exact_one_role_ua(synthetic_pack):
    h=Harness(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1\r\n\r\nx')
    h.connector.fetch_immediate_visit('https://example.com/a',profile_id='immediate_visit_utf8.v2')
    request=h.sockets[0][1].requests[0]
    assert request.count(b'User-Agent:')==1
    assert ('User-Agent: '+UA+'\r\n').encode() in request
    assert b'Accept: */*\r\nAccept-Encoding: identity\r\n' in request
    assert REF.encode() not in request


@pytest.mark.parametrize('version',['v1','v2'])
def test_saved_report_reopens_without_target_get(tmp_path,monkeypatch,synthetic_pack,version):
    tmp_path.chmod(0o700)
    transform=(lambda x:x) if version=='v1' else v2
    claim=ImmediateVisitClaimCredential.model_validate(transform(claim_wire()))
    report=FrozenImmediateVisitReport.from_report(transform(report_wire()))
    journal=ImmediateVisitJournal(tmp_path,claim);journal.prepare_report(claim,report)
    monkeypatch.setattr(ImmediateVisitExecutor,'_fetch',lambda *a,**k:pytest.fail('target refetch'))
    reopened=ImmediateVisitJournal(tmp_path,ImmediateVisitJournal.load_claim(tmp_path,claim.task_id,claim.execution_id))
    assert ImmediateVisitExecutor(journal=reopened).execute(claim,ENDPOINT).canonical_bytes==report.canonical_bytes


@pytest.mark.parametrize('version',['v1','v2'])
def test_version_example_reopens_and_reads_saved_status(tmp_path,monkeypatch,synthetic_pack,version):
    from test_endpoint_choice_reason_integration_prepack import example
    module = example('immediate_visit_versions')
    tmp_path.chmod(0o700)
    transform = (lambda x:x) if version == 'v1' else v2
    credential = ImmediateVisitClaimCredential.model_validate(transform(claim_wire()))
    report = FrozenImmediateVisitReport.from_report(transform(report_wire()))
    journal = ImmediateVisitJournal(tmp_path, credential)
    journal.prepare_report(credential, report)
    payload = transform(status_wire())
    payload['report_sha256'] = report.report_sha256
    exchange = Exchange([raw(payload)])
    selected = []
    def client(**kwargs):
        selected.append(kwargs['version'])
        return AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange), **kwargs)
    monkeypatch.setattr(module, 'AgentImmediateVisitClient', client)
    monkeypatch.setattr(ImmediateVisitExecutor, '_fetch', lambda *a,**k:pytest.fail('target refetch'))
    result = module.resume_saved_report(tmp_path, task_id=TASK, execution_id=EXECUTION)
    assert result.state == 'accepted' and selected == [version]
    assert len(exchange.requests) == 1 and exchange.requests[0][0] == 'GET'
    assert journal.load_report(credential).canonical_bytes == report.canonical_bytes
