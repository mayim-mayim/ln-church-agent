"""Actual fixed B4 + encrypted journal across independent Python processes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_v1_18_14_b4_integration import b4_venue
from test_v1_18_14_b3_integration import LocalExchange, answers, register_followup_blind, tick, wallet
from ln_church_agent._structured_response_crypto import KEY_FILE_ENV, STORAGE_SCHEMA
from ln_church_agent.immediate_visit_journal import _read
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_transport import StructuredResponseError, StructuredResponseTransport


def probe(origin, journal, action, *, without_key=False):
    env = dict(os.environ)
    if without_key:
        env.pop(KEY_FILE_ENV, None)
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('s3_resume_probe.py'))],
        input=json.dumps(dict(origin=origin,directory=str(journal.path.parent),handle=journal.handle,action=action)),
        env=env,check=True,text=True,capture_output=True,timeout=25)
    return json.loads(result.stdout)


def test_actual_b4_encrypted_blind_resume_after_loss_and_expiry(b4_venue, tmp_path):
    origin, state = b4_venue
    class LostReads(LocalExchange):
        block_status = False
        def __call__(self, method, path, query, headers, body, timeout):
            if self.block_status and path.endswith('/status'):
                raise StructuredResponseError('TRANSPORT_ERROR',request_bytes_sent=False)
            return super().__call__(method,path,query,headers,body,timeout)
    exchange = LostReads(origin)
    client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=exchange))
    disclosed = next(t for t in client.list_tasks().tasks if t.aps_kind == 'DISCLOSED')
    d = client.claim(disclosed.task_id,'s3-live',wallet(1),'source-d',journal_directory=tmp_path)
    client.prepare_answer(journal=d.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(disclosed))
    assert client.submit(journal=d.journal).state == 'accepted'
    tick(origin,repeat=25);tick(origin,604800001,repeat=12)
    deep = next(t for t in client.list_tasks().tasks if t.aps_kind == 'DEEP_DIVE')
    dd = client.claim(deep.task_id,'s3-live',wallet(1),'source-deep',journal_directory=tmp_path)
    client.prepare_answer(journal=dd.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(deep))
    assert client.submit(journal=dd.journal).state == 'accepted'
    tick(origin,repeat=25);tick(origin,604800001,repeat=12)
    blind_id = register_followup_blind(origin,state['quote']['study_id'],disclosed.task_id)
    blind = client.get_task(blind_id)
    assert blind.participation == {'mode':'EXCLUDE','source_task_id':None,'source_visibility':'withheld_for_blind'}
    exchange.lose_claim = True
    with pytest.raises(StructuredResponseError) as lost:
        client.claim(blind_id,'s3-live',wallet(30),'original-b-key',journal_directory=tmp_path)
    assert lost.value.code == 'CLAIM_OUTCOME_UNKNOWN'
    journal = StructuredResponseJournal.open(tmp_path,lost.value.journal_handle)
    claim_recovery = probe(origin,journal,'recover_claim')
    assert claim_recovery['state'] == 'claim_recovered'
    assert claim_recovery['before']['claim_key_sha256'] == claim_recovery['after']['claim_key_sha256']
    assert claim_recovery['before']['claim_body_sha256'] == claim_recovery['after']['claim_body_sha256']
    assert claim_recovery['recovery_read_headers'][0] == '1'
    reopened = StructuredResponseJournal.open(tmp_path,journal.handle)
    claim = reopened.load_claim()
    assert claim.context_id == blind.context_id
    frozen = client.prepare_answer(journal=reopened,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(blind))
    exchange.lose_completion = True
    exchange.block_status = True
    assert client.submit(journal=reopened,max_post_requests=1).state == 'unknown'
    stored = _read(journal.path,maximum_bytes=2*1024*1024)
    assert stored['schema_version'] == STORAGE_SCHEMA
    assert claim._claim_token_value().encode() not in journal.path.read_bytes()
    unchanged = journal.path.read_bytes()
    unavailable = probe(origin,journal,'recover_completion',without_key=True)
    assert unavailable == dict(state='recovery_required',code='JOURNAL_KEY_REQUIRED',http_methods=[])
    assert journal.path.read_bytes() == unchanged
    recovered = probe(origin,journal,'recover_completion')
    assert recovered['state'] == 'accepted' and recovered['before'] == recovered['after']
    assert set(recovered['http_methods']) == {'GET'}
    assert recovered['after']['report_sha256'] == frozen.report_sha256
    tick(origin,604800001,repeat=12)
    assert client.get_task(blind_id).status == 'CLOSED'
    expired = probe(origin,journal,'recover_completion')
    assert expired['state'] == 'accepted' and expired['before'] == recovered['after'] == expired['after']
    assert expired['original_receipt_binding_sha256'] == recovered['original_receipt_binding_sha256']
    assert set(expired['http_methods']) == {'GET'}
    assert StructuredResponseJournal.open(tmp_path,journal.handle).load_report().canonical_bytes == frozen.canonical_bytes
    evidence = os.environ.get('LN_CHURCH_S3_PROCESS_EVIDENCE')
    if evidence:
        Path(evidence).write_text(json.dumps(dict(result='PASS',backend_commit='235bc8de9ce60d32e467d2c1476cf9a6eeb6ab0e',
            storage_schema=STORAGE_SCHEMA,algorithm='AES-256-GCM',fresh_process_count=4,
            lost_claim_recovery='same key/body; recovery-read header 1',lost_completion_recovery='GET only; original report bytes/hash',
            claim_expiry_and_task_closure='GET only; original alias/report bytes/hash',
            original_receipt_and_deadlines='same immutable receipt binding hash after expiry/closure',
            blind_source='EXCLUDE / NULL / WITHHELD_FOR_BLIND',key_unavailable='retained identical ciphertext; HTTP 0',
            prepared_report_sha256=frozen.report_sha256,bindings_sha256=hashlib.sha256(json.dumps(expired['after'],sort_keys=True).encode()).hexdigest(),
            parent_sdk_http_exchanges=len(exchange.calls),child_sdk_http_exchanges=sum(len(x['http_methods']) for x in [claim_recovery,recovered,expired]),
            sdk_import_path=expired['sdk_import_path'],real_provider_or_assets=False),indent=2)+'\n')
