"""SDK-W01 regression against exact Backend wire, not SDK-generated positives."""
import copy
import json

import pytest
from pydantic import ValidationError
from ln_church_agent import TaskDiscoveryCandidate, TaskDiscoveryPage
from ln_church_agent.access_quota import AccessQuotaError
from ln_church_agent.task_transport import TaskError
from wire_inputs import FIXTURES, QUOTA
from wire_support import Replay, query_for, run_cli

MIXED = next(x for x in FIXTURES['cases'] if x['name'] == 'mixed-success')
TASKS = MIXED['value']['tasks']
LEGACY = next(x for x in TASKS if x['task_type'] == 'payment_surface_discovery.v1')
ORIGIN = 'https://kari.mayim-mayim.com'


@pytest.mark.parametrize('task', TASKS, ids=lambda t: t['task_type']+'/'+t['task_definition_version'])
def test_all_twelve_original_candidates_keep_every_field(task):
    assert TaskDiscoveryCandidate.model_validate(task).model_dump(mode='json') == task


@pytest.mark.parametrize('case', FIXTURES['cases'], ids=lambda c: c['name'])
def test_fixed_response_model_and_real_client(case):
    ex = Replay(case)
    try:
        if case['status'] == 200:
            assert TaskDiscoveryPage.model_validate(case['value']).model_dump(mode='json') == case['value']
            assert ex.client.discover_tasks(**query_for(case)).model_dump(mode='json') == case['value']
        else:
            with pytest.raises(TaskError) as caught:
                ex.client.discover_tasks(**query_for(case))
            assert caught.value.status_code == case['status']
            assert caught.value.request_bytes_sent is True
            assert caught.value.__context__ is None
        assert len(ex.calls) == 1
        assert set(ex.calls[0]['params']) <= {'limit', 'cursor'}
        assert ex.policy.reserved_atomic == ex.policy.spent_atomic == 0
    finally:
        ex.client.close()


@pytest.mark.parametrize('case', FIXTURES['cases'] + [dict(name='quota-402', **QUOTA)], ids=lambda c: c['name'])
@pytest.mark.parametrize('json_mode', [False, True])
def test_fixed_response_cli_human_and_json(case, json_mode):
    ex = Replay(case)
    row = run_cli(ex.client, query_for(case), json_mode)
    assert len(ex.calls) == 1
    if case['status'] != 200:
        assert row['exitcode'] == 2 and row['stdout'] == ''
        assert 'No candidate count was obtained' in row['stderr']
    else:
        assert row['exitcode'] == 0 and row['stderr'] == ''
        if json_mode:
            assert json.loads(row['stdout']) == case['value']
        else:
            for t in case['value']['tasks']:
                for key in ('task_type', 'task_schema_version', 'task_definition_version',
                            'task_definition_digest', 'detail_url', 'definition_url'):
                    assert t[key] in row['stdout']
            if not case['value']['tasks']:
                assert 'not a global inventory snapshot' in row['stdout']


def legacy_bad_guides():
    guide = LEGACY['definition_url']
    digest = LEGACY['task_definition_digest']
    return [guide.replace(digest+'/', ''), guide.replace(digest, '0'*64),
            guide.replace('payment_surface_discovery.v1', 'immediate_http_visit.v1'),
            guide.replace('/1.0.0/', '/2.0.0/'), guide.replace(ORIGIN, 'https://other.example'),
            guide+'?task_definition_digest='+digest, guide+'#guide',
            guide.replace('/SKILL.md', '/manifest.json')]


@pytest.mark.parametrize('guide', legacy_bad_guides())
def test_legacy_wrong_namespace_digest_origin_or_version_rejects_entire_page(guide):
    wire = copy.deepcopy(MIXED['value'])
    next(t for t in wire['tasks'] if t['task_id'] == LEGACY['task_id'])['definition_url'] = guide
    with pytest.raises(ValidationError):
        TaskDiscoveryPage.model_validate(wire)
    ex = Replay(dict(status=200, value=wire))
    with pytest.raises(TaskError) as caught:
        ex.client.discover_tasks()
    assert caught.value.code == 'TASK_RESPONSE_INVALID' and len(ex.calls) == 1


@pytest.mark.parametrize('digest', [None, '', '0'*64, 'INVALID'])
def test_legacy_original_digest_is_required_and_not_rebuilt(digest):
    task = dict(LEGACY)
    if digest is None:
        del task['task_definition_digest']
    else:
        task['task_definition_digest'] = digest
    with pytest.raises(ValidationError):
        TaskDiscoveryCandidate.model_validate(task)


@pytest.mark.parametrize('task', TASKS, ids=lambda t: t['task_type']+'/'+t['task_definition_version'])
@pytest.mark.parametrize('guard', ['guide_origin', 'guide_version', 'detail_origin', 'detail_selector'])
def test_all_existing_tuple_link_guards_remain(task, guard):
    task = dict(task)
    if guard == 'guide_origin':
        task['definition_url'] = task['definition_url'].replace(ORIGIN, 'https://other.example')
    elif guard == 'guide_version':
        task['definition_url'] = task['definition_url'].replace('/'+task['task_definition_version']+'/', '/99.0.0/')
    elif guard == 'detail_origin':
        task['detail_url'] = task['detail_url'].replace(ORIGIN, 'https://other.example')
    else:
        task['detail_url'] += ('&' if '?' in task['detail_url'] else '?')+'task_type=wrong.v1'
    with pytest.raises(ValidationError):
        TaskDiscoveryCandidate.model_validate(task)


def test_fixed_unusable_quota_challenge_stays_invalid_without_purchase():
    ex = Replay(QUOTA)
    with pytest.raises(AccessQuotaError) as caught:
        ex.client.discover_tasks()
    assert caught.value.code == 'ACCESS_INVALID'
    assert caught.value.origin_not_sent is not True
    assert len(ex.calls) == 1
    assert ex.policy.reserved_atomic == ex.policy.spent_atomic == 0


@pytest.mark.parametrize('case', [c for c in FIXTURES['cases'] if c['status'] == 400], ids=lambda c: c['name'])
def test_fixed_bad_query_is_rejected_before_any_exchange(case):
    ex = Replay(case)
    q = case['query']
    kwargs = dict(limit=int(q.get('limit', '20')), **({'cursor':q['cursor']} if 'cursor' in q else {}))
    with pytest.raises(TaskError) as caught:
        ex.client.discover_tasks(**kwargs)
    assert caught.value.request_bytes_sent is False and ex.calls == []
