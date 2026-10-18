"""c3 alias/source observations through actual SDK with controlled responses.

Oracle: f1f58f129f778150068cb78ee4369d7089c49d3f api-data 1.1,
ui-sdk-csv 3, acceptance SDK01/AC02/05/CT02/03. These fixtures are not
the producer pack, a real Backend closure policy or an eligibility service.
"""
import copy
import hashlib
import json

import pytest

from test_v1_18_14_structured_response_prepack import (
    ADDRESS, ASSUMPTIONS, EXEC, TASK, TOKEN, Venue, answer, claim, error,
    fixture_pack, raw, status, task,
)
from ln_church_agent import structured_response_contract as c
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_models import (
    FrozenStructuredResponseReport, StructuredResponseTask,
)
from ln_church_agent.structured_response_transport import (
    StructuredResponseAPIError, StructuredResponseError, StructuredResponseTransport,
)
from ln_church_agent.task_journal import JournalError

B_CONTEXT = 'ctx_' + 'b' * 32
D_CONTEXT = 'ctx_' + 'd' * 32
OTHER_B_CONTEXT = 'ctx_' + 'c' * 32
D_TASK = 'task_disclosed_source'


def blind_task(mode='EXCLUDE', context_id=B_CONTEXT):
    value = task()
    value['context_id'] = context_id
    value['participation'] = ({'mode': 'ANY'} if mode == 'ANY' else {
        'mode': mode, 'source_task_id': None,
        'source_visibility': 'withheld_for_blind',
    })
    value['terms_digest']=c.digest({key:value[key] for key in c._TERM_FIELDS if key in value})
    return value


class BlindVenue(Venue):
    """Phase/source changes simulate read projections, not Backend behavior."""
    def __init__(self, mode='EXCLUDE', context_id=B_CONTEXT):
        super().__init__(blind_task(mode, context_id))
        self.phase = 'open'
        self.claim_context_id = context_id
        self.context_response_id = context_id
        self.ineligible = False

    def __call__(self, method, path, query, headers, body, timeout):
        if path.endswith(('/claim', '/context', '/status')):
            self.calls.append((method, path, query, dict(headers), body, timeout))
            if path.endswith('/claim'):
                if self.ineligible:
                    return error('participation_ineligible', 409)
                return raw(dict(claim(self.task), context_id=self.claim_context_id))
            if path.endswith('/context'):
                projection = ({'state': 'withheld_for_blind'} if self.phase == 'open'
                              else {'state': 'available', 'source_task_id': D_TASK})
                return raw(dict(schema_version=c.schema('task_context'),
                    task_id=TASK, execution_id=EXEC, context_id=self.context_response_id,
                    context=None, prior=projection))
            if self.report is not None:
                return raw(dict(status(self.report), context_id=self.task['context_id']))
            return error('not_found', 404)
        return super().__call__(method, path, query, headers, body, timeout)


def connect(tmp_path, venue):
    client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=venue))
    operation = client.claim(TASK, 'sdk-c3-test', ADDRESS, 'c3-claim-key',
                             journal_directory=tmp_path)
    return client, operation.journal


def prepare(client, journal):
    return client.prepare_answer(journal=journal,
        shared_assumptions=ASSUMPTIONS, items=[answer()])


@pytest.mark.parametrize('mode', ['ANY', 'INCLUDE', 'EXCLUDE'])
@pytest.mark.parametrize('phase', ['open', 'closed'])
def test_alias_and_withheld_source_complete_python_flow(tmp_path, fixture_pack, mode, phase):
    venue = BlindVenue(mode)
    venue.phase = phase
    client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=venue))
    listed = client.list_tasks().tasks[0]
    detail = client.get_task(TASK)
    assert listed.supported and detail.supported and not detail.update_required
    assert detail.context_id == B_CONTEXT != D_CONTEXT
    assert detail.participation == venue.task['participation']
    op = client.claim(TASK, 'sdk-c3-test', ADDRESS, 'c3-flow-key', journal_directory=tmp_path)
    assert client.recover_claim(journal=op.journal).context_id == B_CONTEXT
    assert client.get_context(journal=op.journal).context_id == B_CONTEXT
    report = prepare(client, op.journal)
    assert report.report['context_id'] == B_CONTEXT
    assert report.report_sha256 == hashlib.sha256(report.canonical_bytes).hexdigest()
    assert client.submit(journal=op.journal).state == 'accepted'
    venue.phase = 'closed'
    reopened = StructuredResponseJournal.open(tmp_path, op.journal.handle)
    assert client.get_submission_status(journal=reopened).context_id == B_CONTEXT
    before = len(venue.calls)
    assert client.recover_completion(journal=reopened).state == 'accepted'
    assert all(call[0] == 'GET' for call in venue.calls[before:])
    assert reopened.load_report().canonical_bytes == report.canonical_bytes
    assert reopened.load_report().report_sha256 == report.report_sha256
    assert all('/aps/' not in call[1] and '/studies/' not in call[1] for call in venue.calls)


@pytest.mark.parametrize('mode', ['INCLUDE', 'EXCLUDE'])
@pytest.mark.parametrize('accepted_before_loss', [False, True])
def test_lost_completion_restart_then_close_retains_exact_alias_and_bytes(
        tmp_path, fixture_pack, mode, accepted_before_loss):
    venue = BlindVenue(mode)
    client, journal = connect(tmp_path, venue)
    frozen = prepare(client, journal)
    venue.fail_posts = 1
    venue.accept_before_loss = accepted_before_loss
    first = client.submit(journal=journal, max_post_requests=1)
    # A lost POST whose acceptance is already visible can resolve via status.
    assert first.state == ('accepted' if accepted_before_loss else 'unknown')
    venue.phase = 'closed'
    # A now-readable source does not replace the Task's alias.
    assert client.get_context(journal=journal).prior['source_task_id'] == D_TASK
    reopened = StructuredResponseJournal.open(tmp_path, journal.handle)
    before = len(venue.calls)
    result = client.recover_completion(journal=reopened)
    assert result.state == 'accepted'
    assert venue.calls[before][1].endswith('/status')
    posts = [call for call in venue.calls if call[1].endswith('/completion')]
    assert len(posts) == (1 if accepted_before_loss else 2)
    assert all(call[4] == frozen.canonical_bytes and
               call[3]['Idempotency-Key'] == frozen.report['submission_id'] for call in posts)
    assert reopened.load_report().report['context_id'] == B_CONTEXT
    assert reopened.load_report().report_sha256 == frozen.report_sha256
    with pytest.raises(JournalError):
        changed = copy.deepcopy(frozen.report)
        changed['context_id'] = D_CONTEXT
        reopened.prepare_report(FrozenStructuredResponseReport.from_report(changed), correction=True)


@pytest.mark.parametrize('mode', ['INCLUDE', 'EXCLUDE'])
def test_withheld_source_does_not_replace_server_eligibility(tmp_path, fixture_pack, mode):
    venue = BlindVenue(mode)
    venue.ineligible = True
    client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=venue))
    assert client.get_task(TASK).supported
    with pytest.raises(StructuredResponseAPIError) as caught:
        client.claim(TASK, 'sdk-c3-test', ADDRESS, 'ineligible-key', journal_directory=tmp_path)
    assert caught.value.public_error_code == 'participation_ineligible'
    assert caught.value.status_code == 409
    assert any(call[1].endswith('/claim') for call in venue.calls)
    assert not any(call[1].endswith('/completion') for call in venue.calls)


@pytest.mark.parametrize('replacement', [D_CONTEXT, OTHER_B_CONTEXT, None])
def test_claim_cannot_rebind_task_context(tmp_path, fixture_pack, replacement):
    venue = BlindVenue()
    venue.claim_context_id = replacement
    with pytest.raises(JournalError):
        connect(tmp_path, venue)
    assert not any(call[1].endswith('/completion') for call in venue.calls)


@pytest.mark.parametrize('replacement', [D_CONTEXT, OTHER_B_CONTEXT, None])
def test_context_read_cannot_rebind_saved_alias(tmp_path, fixture_pack, replacement):
    venue = BlindVenue()
    client, journal = connect(tmp_path, venue)
    venue.context_response_id = replacement
    with pytest.raises(StructuredResponseError, match='RESPONSE_BINDING_INVALID'):
        client.get_context(journal=journal)
    assert journal.load_task().context_id == B_CONTEXT


@pytest.mark.parametrize('replacement', [D_CONTEXT, OTHER_B_CONTEXT, None])
def test_completion_cannot_replace_alias_before_dispatch(tmp_path, fixture_pack, replacement):
    venue = BlindVenue()
    client, journal = connect(tmp_path, venue)
    frozen = prepare(client, journal)
    changed = frozen.report
    changed['context_id'] = replacement
    with pytest.raises(JournalError):
        journal.prepare_report(FrozenStructuredResponseReport.from_report(changed))
    assert journal.load_report().canonical_bytes == frozen.canonical_bytes
    assert not any(call[1].endswith('/completion') for call in venue.calls)


@pytest.mark.parametrize('opaque_id', ['scope~Alias._-123', B_CONTEXT])
def test_wire_context_id_is_opaque_and_echoed_without_derivation(tmp_path, fixture_pack, opaque_id):
    venue = BlindVenue(context_id=opaque_id)
    client, journal = connect(tmp_path, venue)
    assert client.get_context(journal=journal).context_id == opaque_id
    assert prepare(client, journal).report['context_id'] == opaque_id


def test_custom_or_profile_task_may_keep_definition_context_null(tmp_path, fixture_pack):
    venue = BlindVenue('ANY', context_id=None)
    client, journal = connect(tmp_path, venue)
    assert client.get_context(journal=journal).context_id is None
    frozen = prepare(client, journal)
    assert frozen.report['context_id'] is None
    assert client.submit(journal=journal).state == 'accepted'


@pytest.mark.parametrize('invalid', ['', 'context/other', {'id': B_CONTEXT}, 1, 'x' * 129])
def test_invalid_context_id_stops_before_claim(tmp_path, fixture_pack, invalid):
    venue = BlindVenue(context_id=invalid)
    with pytest.raises(StructuredResponseError, match='RESPONSE_INVALID'):
        connect(tmp_path, venue)
    assert not any(call[1].endswith('/claim') for call in venue.calls)


@pytest.mark.parametrize('participation', [
    {'mode': 'INCLUDE', 'source_task_id': None},
    {'mode': 'EXCLUDE', 'source_task_id': D_TASK, 'source_visibility': 'withheld_for_blind'},
    {'mode': 'ANY', 'source_task_id': None, 'source_visibility': 'withheld_for_blind'},
    {'mode': 'WITHHELD', 'source_task_id': None},
])
def test_withheld_metadata_is_not_a_new_mode_or_visible_source(fixture_pack, participation):
    value = blind_task()
    value['participation'] = participation
    with pytest.raises(ValueError):
        StructuredResponseTask(value)


@pytest.mark.parametrize('mode', ['INCLUDE', 'EXCLUDE'])
def test_disclosed_source_representation_remains_supported(fixture_pack, mode):
    value = task()
    value['participation'] = {'mode': mode, 'source_task_id': D_TASK}
    value['terms_digest']=c.digest({key:value[key] for key in c._TERM_FIELDS if key in value})
    parsed = StructuredResponseTask(value)
    assert parsed.supported and parsed.participation == value['participation']


@pytest.mark.parametrize('mode', ['INCLUDE', 'EXCLUDE'])
def test_mcp_responder_preserves_alias_across_unknown_restart_and_close(
        tmp_path, fixture_pack, monkeypatch, mode):
    from ln_church_agent.integrations import mcp_structured_response as m
    venue = BlindVenue(mode)
    transport = StructuredResponseTransport(exchange=venue)
    monkeypatch.setattr(m, 'StructuredResponseClient', lambda: StructuredResponseClient(transport=transport))
    monkeypatch.setattr(m, '_directory', lambda: tmp_path)
    class Registry:
        def __init__(self):
            self.tools = {}
        def tool(self):
            def save(function):
                self.tools[function.__name__] = function
                return function
            return save
    registry = Registry()
    m.register_tools(registry)
    ops = registry.tools
    detail = ops['structured_response_get_task'](TASK)
    assert not detail['read_only'] and not detail['update_required']
    assert detail['task']['participation'] == venue.task['participation']
    op = ops['structured_response_claim'](TASK, 'sdk-c3-test', ADDRESS, 'mcp-c3-key')
    handle = op['journal_handle']
    assert op['claim']['context_id'] == B_CONTEXT
    assert ops['structured_response_get_context'](handle)['context_id'] == B_CONTEXT
    prepared = ops['structured_response_prepare_answer'](handle, ASSUMPTIONS, [answer()])
    saved = StructuredResponseJournal.open(tmp_path, handle).load_report()
    venue.fail_posts = 5
    assert ops['structured_response_submit'](handle)['state'] == 'unknown'
    venue.phase = 'closed'
    venue.fail_posts = 0
    recovered = ops['structured_response_recover_completion'](handle)
    assert recovered['state'] == 'accepted'
    assert ops['structured_response_get_submission_status'](handle)['context_id'] == B_CONTEXT
    assert StructuredResponseJournal.open(tmp_path, handle).load_report().canonical_bytes == saved.canonical_bytes
    posts = [call for call in venue.calls if call[1].endswith('/completion')]
    assert len(posts) == 4
    assert all(call[4] == saved.canonical_bytes and
               call[3]['Idempotency-Key'] == prepared['submission_id'] for call in posts)
    assert TOKEN not in json.dumps([detail, op, prepared, recovered])
    assert all('/aps/' not in call[1] and '/studies/' not in call[1] for call in venue.calls)
