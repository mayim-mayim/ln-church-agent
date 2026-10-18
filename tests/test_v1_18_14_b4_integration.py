"""S2 wheel against the exact B4 HTTP factories; synthetic adapters only.

S1's broader B3 tests/evidence remain historical. This test exercises the new
pack identity and unchanged responder binding at the B4 D/deep/B boundary.
"""
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import requests

from test_v1_18_14_b3_integration import (
    LocalExchange, answers, register_followup_blind, tick, wallet,
)
from ln_church_agent import structured_response_contract as c
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_transport import (
    StructuredResponseError, StructuredResponseTransport,
)

B4_COMMIT = '235bc8de9ce60d32e467d2c1476cf9a6eeb6ab0e'
B4_DIGEST = '4d2b8f711b2273fba5215bbcfd767df1145d30a91ee9ea5711437e791616b274'


@pytest.fixture
def b4_venue(tmp_path):
    directory = os.environ.get('LN_CHURCH_B4_TEST_ROOT')
    if not directory:
        pytest.skip('Exact fixed B4 root is not configured.')
    state = tmp_path / 'b4-state.json'
    with (tmp_path / 'b4-server.log').open('w') as log:
        server = subprocess.Popen(['node', 'tests/v1814/isolated-api.mjs'],
            cwd=directory, stdout=log, stderr=log,
            env=dict(os.environ, APS_ISOLATED_B4='1', APS_ISOLATED_PORT='0',
                APS_ISOLATED_STATE_FILE=str(state)))
        try:
            deadline = time.monotonic() + 20
            while not state.exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Fixed B4 isolated API did not start.')
                time.sleep(.05)
            origin = json.loads(state.read_text())['base_url'].removesuffix('/api')
            response = requests.get(origin + '/_isolated/state', timeout=5)
            assert response.status_code == 200
            yield origin, response.json()
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def test_actual_b4_pack_explicit_answer_and_original_binding(b4_venue, tmp_path, monkeypatch):
    origin, state = b4_venue
    exchange = LocalExchange(origin)
    transport = StructuredResponseTransport(exchange=exchange)
    client = StructuredResponseClient(transport=transport)
    task = next(t for t in client.list_tasks().tasks if t.aps_kind == 'DISCLOSED')
    assert task.supported and task.task_definition_digest == B4_DIGEST
    assert c.PACK_SOURCE['commit'] == B4_COMMIT
    task = client.get_task(task.task_id)
    exchange.lose_claim = True
    with pytest.raises(StructuredResponseError) as lost:
        client.claim(task.task_id, 's2-isolated', wallet(1), 's2-d', journal_directory=tmp_path)
    assert lost.value.code == 'CLAIM_OUTCOME_UNKNOWN'
    journal = StructuredResponseJournal.open(tmp_path, lost.value.journal_handle)
    claim = client.recover_claim(journal=journal)
    assert exchange.calls[-1]['recovery_read'] == '1'
    context = client.get_context(journal=journal)
    assert context.context_id == claim.context_id == task.context_id
    items = answers(task)
    for item in items:
        if item['item_id'] == 'category':
            item.update(status='answered', value={'name': 'Synthetic category'})
        elif item['item_id'] == 'competitors':
            item.update(status='answered', value={'candidates': [
                {'name': 'Synthetic alternative', 'url': 'https://alternative.example/'}]})
    frozen = client.prepare_answer(journal=journal,
        shared_assumptions={'must': '', 'volume': '', 'outcome': ''}, items=items)
    exchange.lose_completion = True
    assert client.submit(journal=journal).state == 'accepted'
    assert client.get_submission_status(journal=journal).report_sha256 == frozen.report_sha256
    tick(origin, repeat=25)
    tick(origin, 604800001, repeat=12)
    assert client.get_task(task.task_id).status == 'CLOSED'

    deep = next(t for t in client.list_tasks().tasks if t.aps_kind == 'DEEP_DIVE')
    assert deep.supported and deep.task_definition_digest == B4_DIGEST
    assert deep.participation['source_task_id'] == task.task_id
    op = client.claim(deep.task_id, 's2-isolated', wallet(1), 's2-deep', journal_directory=tmp_path)
    deep_context = client.get_context(journal=op.journal)
    assert deep_context.task_id == deep.task_id
    assert deep_context.execution_id == op.claim.execution_id
    assert deep_context.context_id == op.claim.context_id == deep.context_id
    prior = deep_context.model_dump()['prior']
    assert prior['state'] == 'AVAILABLE'
    assert prior['prior_answer']['task_id'] == task.task_id
    assert prior['prior_answer']['submission_id'] == frozen.report['submission_id']
    prior_sha256 = hashlib.sha256(c.canonical_bytes(prior)).hexdigest()
    deep_frozen = client.prepare_answer(journal=op.journal,
        shared_assumptions={'must': '', 'volume': '', 'outcome': ''}, items=answers(deep))
    assert deep_frozen.report['context_id'] == deep_context.context_id
    assert client.submit(journal=op.journal).state == 'accepted'
    token = op.claim._claim_token_value()
    replay = requests.post(origin + c.task_completion_path(deep.task_id),
        data=deep_frozen.canonical_bytes, timeout=10, allow_redirects=False,
        headers={'Content-Type': 'application/json', 'X-LN-Task-Claim-Token': token,
            'Idempotency-Key': deep_frozen.report['submission_id']})
    assert replay.status_code == 200
    assert replay.json()['report_sha256'] == deep_frozen.report_sha256

    tick(origin, repeat=25)
    tick(origin, 604800001, repeat=12)
    assert client.get_task(deep.task_id).status == 'CLOSED'

    # Test-only requester HTTP fixture; no new requester SDK operation.
    blind_id = register_followup_blind(origin, state['quote']['study_id'], task.task_id)
    blind = client.get_task(blind_id)
    assert blind.supported and blind.task_definition_digest == B4_DIGEST
    assert blind.participation == {'mode': 'EXCLUDE', 'source_task_id': None,
        'source_visibility': 'withheld_for_blind'}
    assert blind.context_id != task.context_id
    from ln_church_agent.integrations import mcp_structured_response as m
    monkeypatch.setattr(m, 'StructuredResponseClient', lambda: StructuredResponseClient(transport=transport))
    monkeypatch.setattr(m, '_directory', lambda: tmp_path)
    class Registry:
        def __init__(self): self.tools = {}
        def tool(self):
            def save(f): self.tools[f.__name__] = f; return f
            return save
    registry = Registry()
    m.register_tools(registry)
    ops = registry.tools
    assert len(ops) == 10
    assert any(t['task_id'] == blind_id for t in ops['structured_response_list_tasks']()['tasks'])
    assert not ops['structured_response_get_task'](blind_id)['read_only']
    selected = ops['structured_response_claim'](blind_id, 's2-mcp', wallet(30), 's2-b-mcp')
    handle = selected['journal_handle']
    assert ops['structured_response_recover_claim'](handle)['context_id'] == blind.context_id
    assert ops['structured_response_get_context'](handle)['context_id'] == blind.context_id
    ops['structured_response_prepare_answer'](handle, {'must': '', 'volume': '', 'outcome': ''}, answers(blind))
    assert ops['structured_response_submit'](handle)['state'] == 'accepted'
    saved_blind = StructuredResponseJournal.open(tmp_path, handle).load_report()
    assert ops['structured_response_get_submission_status'](handle)['report_sha256'] == saved_blind.report_sha256
    abandoned = ops['structured_response_claim'](blind_id, 's2-mcp', wallet(31), 's2-b-abandon')
    assert ops['structured_response_abandon'](abandoned['journal_handle'], 's2-abandon')['state'] == 'abandoned'
    tick(origin, 604800001, repeat=12)
    assert client.get_task(blind_id).status == 'CLOSED'
    assert ops['structured_response_recover_completion'](handle)['state'] == 'accepted'
    assert StructuredResponseJournal.open(tmp_path, handle).load_report().canonical_bytes == saved_blind.canonical_bytes
    reopened = StructuredResponseJournal.open(tmp_path, op.journal.handle)
    before = len(exchange.calls)
    assert client.recover_completion(journal=reopened).state == 'accepted'
    assert all(call['method'] == 'GET' for call in exchange.calls[before:])
    assert reopened.load_report().canonical_bytes == deep_frozen.canonical_bytes
    assert hashlib.sha256(c.canonical_bytes(client.get_context(journal=reopened).model_dump()['prior'])).hexdigest() == prior_sha256
    assert client.recover_completion(journal=journal).state == 'accepted'
    assert journal.load_report().canonical_bytes == frozen.canonical_bytes
    assert client.get_submission_status(journal=reopened).payout['state'] != 'paid_confirmed'

    destination = os.environ.get('LN_CHURCH_B4_SDK_EVIDENCE')
    if destination:
        Path(destination).write_text(json.dumps({
            'result': 'PASS', 'backend_commit': B4_COMMIT, 'v3_digest': B4_DIGEST,
            'sdk_import_path': c.__file__, 'operations': list(ops),
            'http_exchanges': len(exchange.calls), 'manual_same_bytes_replay_http': replay.status_code,
            'deep_report_sha256': deep_frozen.report_sha256, 'deep_prior_sha256': prior_sha256,
            'deep_source_binding': 'original D Task/submission; frozen prior unchanged after closure',
            'blind_source': 'EXCLUDE / NULL / WITHHELD_FOR_BLIND',
            'recovery': 'original alias/report bytes/hash after Claim expiry and Task closure',
            'transport': 'test-only pinned loopback, redirects disabled',
            'substitutions': 'fixed B4 synthetic provider/storage/chain/signature; settlement pending',
            'real_provider_or_assets': False,
        }, indent=2) + '\n')
