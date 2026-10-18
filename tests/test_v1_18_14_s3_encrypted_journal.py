"""F07: authenticated disk storage, separate operator key and same-journal resume."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ln_church_agent import structured_response_contract as c
from ln_church_agent._structured_response_crypto import KEY_FILE_ENV, STORAGE_SCHEMA
from ln_church_agent.immediate_visit_journal import _read, _write
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_models import FrozenStructuredResponseReport
from ln_church_agent.structured_response_transport import StructuredResponseTransport
from ln_church_agent.task_journal import JournalError
from test_v1_18_14_final_contract import supported_task
from test_v1_18_14_structured_response_prepack import ADDRESS, TOKEN, claim, raw


def prepared(directory):
    task = supported_task()
    journal = StructuredResponseJournal(directory, task_id=task['task_id'], agent_id='s3-test',
        reward_address=ADDRESS, idempotency_key='s3-saved-key')
    journal.save_task(task)
    journal.begin_claim()
    credential = claim(task)
    credential['task_definition_digest'] = task['task_definition_digest']
    journal.save_claim(credential)
    report = dict(schema_version=c.schema('task_completion'), task_id=task['task_id'],
        task_type=task['task_type'], task_definition_version=task['task_definition_version'],
        task_definition_digest=task['task_definition_digest'], terms_digest=task['terms_digest'],
        execution_id=credential['execution_id'], submission_id='sub_'+'1'*32,
        context_id=task['context_id'], shared_assumptions={'must':'','volume':'','outcome':''},
        items=[{'item_id':'answer_1','status':'answered','value':'Private synthetic answer.',
                'reason':'A controlled test explanation.'}])
    frozen = FrozenStructuredResponseReport.from_report(report)
    journal.prepare_report(frozen)
    journal.record_dispatch()
    return journal, frozen


def snapshot(journal):
    return dict(logical_sha256=c.digest(journal._load()),
        token_sha256=hashlib.sha256(journal.load_claim()._claim_token_value().encode()).hexdigest(),
        report_sha256=journal.load_report().report_sha256,
        claim_request_sha256=hashlib.sha256(journal.claim_request()[2]).hexdigest())


def test_ciphertext_only_and_another_process_keeps_original_state(tmp_path):
    journal, frozen = prepared(tmp_path)
    disk = journal.path.read_bytes()
    key = Path(os.environ[KEY_FILE_ENV]).read_bytes()
    assert TOKEN.encode() not in disk and key not in disk and key.hex().encode() not in disk
    assert b'Private synthetic answer.' not in disk
    stored = _read(journal.path, maximum_bytes=2*1024*1024)
    assert stored['schema_version'] == STORAGE_SCHEMA and stored['algorithm'] == 'AES-256-GCM'
    assert 'credential' not in stored and 'claim_token' not in stored
    expected = snapshot(journal)
    script = '''import json,sys,hashlib
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent import structured_response_contract as c
j=StructuredResponseJournal.open(sys.argv[1],sys.argv[2])
print(json.dumps(dict(logical_sha256=c.digest(j._load()),token_sha256=hashlib.sha256(j.load_claim()._claim_token_value().encode()).hexdigest(),report_sha256=j.load_report().report_sha256,claim_request_sha256=hashlib.sha256(j.claim_request()[2]).hexdigest())))
'''
    run = subprocess.run([sys.executable,'-c',script,str(tmp_path),journal.handle],
        check=True, capture_output=True, text=True)
    assert json.loads(run.stdout) == expected
    assert TOKEN not in run.stdout+run.stderr
    assert journal.load_report().canonical_bytes == frozen.canonical_bytes
    if os.name != 'nt':
        assert journal.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('failure,code', [('missing','JOURNAL_KEY_REQUIRED'),
    ('unavailable','JOURNAL_KEY_UNAVAILABLE'),('wrong','JOURNAL_KEY_MISMATCH')])
def test_key_failure_preserves_ciphertext_and_restoration_resumes(tmp_path, monkeypatch, failure, code):
    journal, frozen = prepared(tmp_path)
    original = os.environ[KEY_FILE_ENV]
    disk = journal.path.read_bytes()
    if failure == 'missing': monkeypatch.delenv(KEY_FILE_ENV)
    elif failure == 'unavailable': monkeypatch.setenv(KEY_FILE_ENV, original+'.missing')
    else:
        wrong = Path(original).with_name('wrong.key');wrong.write_bytes(os.urandom(32));wrong.chmod(0o600)
        monkeypatch.setenv(KEY_FILE_ENV,str(wrong))
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code == code
    assert TOKEN not in str(caught.value)+repr(caught.value)
    assert journal.path.read_bytes() == disk
    monkeypatch.setenv(KEY_FILE_ENV,original)
    resumed = StructuredResponseJournal.open(tmp_path,journal.handle)
    assert resumed.load_report().canonical_bytes == frozen.canonical_bytes


@pytest.mark.parametrize('field', ['ciphertext','tag','nonce','algorithm'])
def test_authenticated_storage_tamper_is_refused_without_rewrite(tmp_path, field):
    journal, _ = prepared(tmp_path)
    stored = _read(journal.path, maximum_bytes=2*1024*1024)
    value = stored[field]
    stored[field] = ('A' if value[0] != 'A' else 'B')+value[1:]
    _write(journal.path,stored,maximum_bytes=2*1024*1024)
    disk = journal.path.read_bytes()
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code == 'JOURNAL_DECRYPTION_FAILED'
    assert journal.path.read_bytes() == disk


def test_swapped_journal_handle_is_refused(tmp_path):
    journal, _ = prepared(tmp_path)
    stored = _read(journal.path, maximum_bytes=2*1024*1024)
    stored['journal_handle'] = 'f'*64
    _write(journal.path,stored,maximum_bytes=2*1024*1024)
    disk = journal.path.read_bytes()
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code == 'JOURNAL_STATE_CONFLICT'
    assert journal.path.read_bytes() == disk


def test_legacy_s2_rewrite_preserves_claim_report_and_unknown_dispatch(tmp_path, monkeypatch):
    journal, frozen = prepared(tmp_path)
    logical = journal._load()
    _write(journal.path,logical,maximum_bytes=2*1024*1024)  # exact S2 envelope format
    legacy_bytes = journal.path.read_bytes()
    assert TOKEN.encode() in legacy_bytes
    original = os.environ[KEY_FILE_ENV]
    monkeypatch.delenv(KEY_FILE_ENV)
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code == 'JOURNAL_KEY_REQUIRED'
    assert journal.path.read_bytes() == legacy_bytes
    monkeypatch.setenv(KEY_FILE_ENV,original)
    resumed = StructuredResponseJournal.open(tmp_path,journal.handle)
    assert resumed._load() == logical
    assert resumed.load_report().canonical_bytes == frozen.canonical_bytes
    assert resumed.completion_started()
    assert TOKEN.encode() not in journal.path.read_bytes()
    assert _read(journal.path,maximum_bytes=2*1024*1024)['schema_version'] == STORAGE_SCHEMA


def test_missing_key_blocks_new_claim_before_any_network(tmp_path, monkeypatch):
    calls = []
    def exchange(method,path,query,headers,body,timeout):
        calls.append(method);return raw(supported_task())
    monkeypatch.delenv(KEY_FILE_ENV)
    client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=exchange))
    with pytest.raises(JournalError) as caught:
        client.claim(supported_task()['task_id'],'s3',ADDRESS,'same-key',journal_directory=tmp_path)
    assert caught.value.code == 'JOURNAL_KEY_REQUIRED' and calls == []
    assert not list(tmp_path.glob('*.structured-response.json'))


def test_encryption_failure_cannot_replace_legacy_bytes(tmp_path, monkeypatch):
    journal, _ = prepared(tmp_path)
    _write(journal.path,journal._load(),maximum_bytes=2*1024*1024)
    legacy=journal.path.read_bytes()
    from ln_church_agent import _structured_response_crypto as crypto
    def fail(*args,**kwargs): raise ValueError('never surface a cipher diagnostic')
    monkeypatch.setattr(crypto.AES,'new',fail)
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code=='JOURNAL_ENCRYPTION_FAILED'
    assert journal.path.read_bytes()==legacy
    assert 'cipher diagnostic' not in str(caught.value)


def test_migration_persistence_failure_retains_original_journal(tmp_path, monkeypatch):
    journal, _ = prepared(tmp_path)
    _write(journal.path,journal._load(),maximum_bytes=2*1024*1024)
    legacy=journal.path.read_bytes()
    from ln_church_agent import immediate_visit_journal as private_io
    def fail(*args,**kwargs): raise OSError('never surface a storage diagnostic')
    monkeypatch.setattr(private_io.os,'replace',fail)
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code=='JOURNAL_PERSISTENCE_AMBIGUOUS'
    assert journal.path.read_bytes()==legacy
    assert not list(tmp_path.glob('*.tmp'))


def test_writes_refresh_nonce_without_changing_saved_report(tmp_path):
    journal, frozen = prepared(tmp_path)
    first=_read(journal.path,maximum_bytes=2*1024*1024)
    before=journal._load()
    journal.record_dispatch()
    second=_read(journal.path,maximum_bytes=2*1024*1024)
    assert first['nonce']!=second['nonce']
    assert journal._load()==before
    assert journal.load_report().canonical_bytes==frozen.canonical_bytes


def test_actual_s2_wheel_journal_is_migrated_without_binding_change(tmp_path):
    site=os.environ.get('LN_CHURCH_S2_WHEEL_SITE')
    if not site: pytest.skip('Historical fixed S2 wheel site is not configured.')
    journal, frozen=prepared(tmp_path)
    logical=journal._load()
    script='''import json,sys
from pathlib import Path
from ln_church_agent.immediate_visit_journal import _write
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent import structured_response_contract as c
request=json.load(sys.stdin)
path=Path(request['directory'])/(request['handle']+'.structured-response.json')
_write(path,request['logical'],maximum_bytes=2*1024*1024)
j=StructuredResponseJournal.open(request['directory'],request['handle'])
print(json.dumps(dict(logical_sha256=c.digest(j._load()),sdk_import_path=c.__file__)))
'''
    result=subprocess.run([sys.executable,'-c',script],check=True,capture_output=True,text=True,
        input=json.dumps(dict(directory=str(tmp_path),handle=journal.handle,logical=logical)),
        env=dict(os.environ,PYTHONPATH=site))
    output=json.loads(result.stdout)
    assert output['logical_sha256']==c.digest(logical)
    assert Path(output['sdk_import_path']).is_relative_to(Path(site))
    assert TOKEN not in result.stdout+result.stderr
    assert TOKEN.encode() in journal.path.read_bytes()
    resumed=StructuredResponseJournal.open(tmp_path,journal.handle)
    assert resumed._load()==logical
    assert resumed.load_report().canonical_bytes==frozen.canonical_bytes
    assert TOKEN.encode() not in journal.path.read_bytes()


def test_mcp_key_failure_is_explicit_recoverable_and_secret_free(tmp_path, monkeypatch):
    journal, _ = prepared(tmp_path)
    from ln_church_agent.integrations import mcp_structured_response as m
    class Registry:
        def __init__(self):self.tools={}
        def tool(self):
            def save(f):self.tools[f.__name__]=f;return f
            return save
    monkeypatch.setattr(m,'_directory',lambda:tmp_path)
    registry=Registry();m.register_tools(registry)
    monkeypatch.delenv(KEY_FILE_ENV)
    result=registry.tools['structured_response_recover_claim'](journal.handle)
    assert result == dict(state='recovery_required',code='JOURNAL_KEY_REQUIRED',recoverable=True,
        recovery_action='configure_original_key_file_and_retry_same_journal')
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize('kind', ['length','file_mode','directory_mode','symlink','hardlink','inside_journal','relative'])
def test_unsafe_key_configuration_cannot_load_or_rewrite(tmp_path, monkeypatch, kind):
    journal, _ = prepared(tmp_path)
    original = Path(os.environ[KEY_FILE_ENV])
    if kind == 'length': original.write_bytes(b'x'*31)
    elif kind == 'file_mode': original.chmod(0o644)
    elif kind == 'directory_mode': original.parent.chmod(0o755)
    elif kind == 'symlink':
        path=original.with_name('linked.key');path.symlink_to(original);monkeypatch.setenv(KEY_FILE_ENV,str(path))
    elif kind == 'hardlink': os.link(original,original.with_name('hard.key'))
    elif kind == 'inside_journal':
        path=tmp_path/'same-folder.key';path.write_bytes(original.read_bytes());path.chmod(0o600)
        monkeypatch.setenv(KEY_FILE_ENV,str(path))
    else: monkeypatch.setenv(KEY_FILE_ENV,'relative.key')
    disk=journal.path.read_bytes()
    with pytest.raises(JournalError) as caught: StructuredResponseJournal.open(tmp_path,journal.handle)
    assert caught.value.code == 'JOURNAL_KEY_UNAVAILABLE'
    assert journal.path.read_bytes()==disk
