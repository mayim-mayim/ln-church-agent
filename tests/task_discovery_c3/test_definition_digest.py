"""TD-T2-F01 scoped regression using unchanged Backend wire and formal pins."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
import ln_church_agent
from ln_church_agent import TaskDiscoveryCandidate, TaskDiscoveryPage
from ln_church_agent.task_transport import TaskError
from wire_inputs import FIXTURES
from wire_support import Replay, run_cli
from formal_identities import IDENTITIES

MIXED = next(c for c in FIXTURES['cases'] if c['name'] == 'mixed-success')
TASKS = MIXED['value']['tasks']


@pytest.mark.parametrize('task', TASKS, ids=lambda t: t['task_type']+'/'+t['task_definition_version'])
def test_normal_candidate_matches_existing_formal_identity_and_keeps_original_fields(task):
    identity = next(i for i in IDENTITIES if (i['task_type'], i['version']) ==
                    (task['task_type'], task['task_definition_version']))
    assert (task['task_schema_version'], task['task_definition_digest']) == (identity['schema'], identity['digest'])
    if identity['path'].startswith('ln_church_agent/'):
        raw = (Path(ln_church_agent.__file__).parent.parent/identity['path']).read_bytes()
        assert len(raw) == identity['bytes']
        assert hashlib.sha256(raw).hexdigest() == identity['sha256']
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == identity['blob']
        manifest = json.loads(raw)
        assert (manifest['task_type'], manifest['task_definition_version'], manifest['task_definition_digest']) == (
            task['task_type'], task['task_definition_version'], task['task_definition_digest'])
    assert TaskDiscoveryCandidate.model_validate(task).model_dump(mode='json') == task


def assert_invalid(case, channel):
    if channel == 'model':
        with pytest.raises(ValidationError):
            TaskDiscoveryPage.model_validate(case['value'])
        return
    ex = Replay(case)
    if channel == 'client':
        try:
            with pytest.raises(TaskError) as caught:
                ex.client.discover_tasks()
            assert caught.value.code == 'TASK_RESPONSE_INVALID'
            assert caught.value.request_bytes_sent is True
            assert caught.value.__context__ is None and caught.value.__cause__ is None
            assert 'PRIVATE_MARKER' not in str(caught.value)+repr(vars(caught.value))
        finally:
            ex.client.close()
    else:
        output = run_cli(ex.client, json_mode=channel == 'CLI-json')
        assert output['exitcode'] == 2 and output['stdout'] == ''
        assert 'No candidate count was obtained' in output['stderr']
        assert 'PRIVATE_MARKER' not in output['stderr']
    assert len(ex.calls) == 1
    assert ex.policy.spent_atomic == ex.policy.reserved_atomic == 0


@pytest.mark.parametrize('task', TASKS, ids=lambda t: t['task_type']+'/'+t['task_definition_version'])
@pytest.mark.parametrize('channel', ['model', 'client', 'CLI-human', 'CLI-json'])
def test_valid_format_wrong_digest_is_not_a_candidate_or_empty_success(task, channel):
    case = copy.deepcopy(MIXED)
    case['value']['tasks'] = [copy.deepcopy(task)]
    case['value']['tasks'][0]['task_definition_digest'] = '0'*64
    assert_invalid(case, channel)


@pytest.mark.parametrize('channel', ['model', 'client', 'CLI-human', 'CLI-json'])
def test_mixed_page_is_rejected_whole_instead_of_dropping_one_bad_candidate(channel):
    case = copy.deepcopy(MIXED)
    t = next(t for t in case['value']['tasks'] if t['task_schema_version'].endswith('.v2_1'))
    t['task_definition_digest'] = '0'*64
    t['private_pointer'] = 'PRIVATE_MARKER'
    case['value']['private_meta'] = 'PRIVATE_MARKER'
    assert_invalid(case, channel)


@pytest.mark.parametrize('version,other', [('2.0.0', '2.1.0'), ('2.1.0', '2.0.0')])
def test_choice_versions_cannot_exchange_other_valid_formal_digest(version, other):
    original = next(t for t in TASKS if t['task_type'] == 'endpoint_choice_reason.v2' and t['task_definition_version'] == version)
    other_task = next(t for t in TASKS if t['task_type'] == original['task_type'] and t['task_definition_version'] == other)
    changed = dict(original, task_definition_digest=other_task['task_definition_digest'])
    with pytest.raises(ValidationError):
        TaskDiscoveryCandidate.model_validate(changed)


def test_legacy_arbitrary_digest_cannot_pass_by_changing_both_digest_and_guide():
    task = dict(next(t for t in TASKS if t['task_type'] == 'payment_surface_discovery.v1'))
    task['definition_url'] = task['definition_url'].replace(task['task_definition_digest'], '0'*64)
    task['task_definition_digest'] = '0'*64
    with pytest.raises(ValidationError):
        TaskDiscoveryCandidate.model_validate(task)


@pytest.mark.parametrize('json_mode', [False, True])
def test_unmodified_twelve_tuple_mixed_success_reaches_real_client_and_cli(json_mode):
    ex = Replay(MIXED)
    model = ex.client.discover_tasks()
    assert model.model_dump(mode='json') == MIXED['value']
    assert len(ex.calls) == 1
    ex.client.close()
    ex = Replay(MIXED)
    output = run_cli(ex.client, json_mode=json_mode)
    assert output['exitcode'] == 0 and output['stderr'] == ''
    assert len(ex.calls) == 1
    if json_mode:
        assert json.loads(output['stdout']) == MIXED['value']
    else:
        for t in TASKS:
            for field in ('task_definition_digest', 'detail_url', 'definition_url'):
                assert t[field] in output['stdout']
