"""Actual fixed B3 HTTP factories + SDK; providers/chain/EOA are synthetic.

Set LN_CHURCH_B3_TEST_ROOT to the materialized exact Backend tree. Tokens and
raw DTOs stay in temporary directories and are not returned as evidence.
"""
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

import pytest
import requests

from ln_church_agent import structured_response_contract as c
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_models import StructuredResponseTask
from ln_church_agent.structured_response_transport import (
    StructuredResponseError, StructuredResponseTransport,
)
from ln_church_agent.immediate_visit_transport import ImmediateVisitRawResponse
from ln_church_agent.task_journal import JournalError


class LocalExchange:
    """Test-only loopback pin; leaves SDK's production origin/resolver intact."""
    def __init__(self, origin):
        assert origin.startswith('http://127.0.0.1:')
        self.origin = origin
        self.calls = []
        self.lose_claim = False
        self.lose_completion = False
        self.corrupt_completion = False

    def __call__(self, method, path, query, headers, body, timeout):
        assert path.startswith('/api/agent/tasks')
        self.calls.append({'method':method, 'path':path, 'body':body,
            'key':headers.get('Idempotency-Key'), 'recovery_read':headers.get('X-LN-Claim-Recovery')})
        sent = body
        if self.corrupt_completion and path.endswith('/completion'):
            self.corrupt_completion = False
            payload = json.loads(body)
            payload['items'][0]['status'] = 'structurally_invalid'
            sent = c.canonical_bytes(payload)
        response = requests.request(method, self.origin + path + (('?' + query) if query else ''),
            headers=headers, data=sent, timeout=timeout, allow_redirects=False)
        self.calls[-1]['http_status'] = response.status_code
        self.calls[-1]['response_keys'] = list(response.json())
        if self.lose_claim and path.endswith('/claim'):
            self.lose_claim = False
            raise StructuredResponseError('TRANSPORT_ERROR', request_bytes_sent=True)
        if self.lose_completion and path.endswith('/completion'):
            self.lose_completion = False
            raise StructuredResponseError('TRANSPORT_ERROR', request_bytes_sent=True)
        return ImmediateVisitRawResponse(response.status_code, dict(response.headers), response.content)


@pytest.fixture
def venue(tmp_path):
    directory = os.environ.get('LN_CHURCH_B3_TEST_ROOT')
    if not directory:
        pytest.skip('Exact isolated Backend root is not configured.')
    state = tmp_path/'isolated-state.json'
    log = (tmp_path/'isolated-server.log').open('w')
    env = dict(os.environ, APS_ISOLATED_PORT='0', APS_ISOLATED_STATE_FILE=str(state))
    server = subprocess.Popen(['node', 'tests/v1814/isolated-api.mjs'], cwd=directory,
        env=env, stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 20
        while not state.exists():
            if server.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('The fixed isolated Backend did not start.')
            time.sleep(.05)
        data = json.loads(state.read_text())
        origin = data['base_url'].removesuffix('/api')
        yield origin, requests.get(origin+'/_isolated/state', timeout=5).json()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill(); server.wait()
        log.close()


def tick(origin, advance=0, repeat=5):
    for n in range(repeat):
        response = requests.post(origin+'/_isolated/tick', json={'advance_ms':advance if n==0 else 0}, timeout=20)
        assert response.status_code == 200


def wallet(n):
    return '0x'+format(n, '040x')


def answers(task, *, profile=False):
    return [dict(item_id=item['item_id'], status='not_disclosed' if profile else 'unknown',
        value=None, reason='This is outside the information or disclosure scope available to me.')
        for item in task.items if item['required']]


def register_custom(origin):
    item=dict(item_id='answer',question={'en':'Describe your available execution environment.'},
        kind='text',required=True,allowed_statuses=['answered','unknown'],
        quality_condition='Give a reasoned answer to the question.',content_conditions=[])
    payload=dict(schema_version='ln_church.structured_response_quote_request.v1',
        quote_key='sdk-'+secrets.token_hex(12),quote_token=secrets.token_hex(32),plan_id='C5',
        registration=dict(task_type=c.TASK_TYPE,title='SDK isolated structural check',description='',
            items=[item],participation={'mode':'ANY'},private_reference_items=[]))
    quote=requests.post(origin+'/api/agent/structured-response/quotes',json=payload,timeout=10)
    assert quote.status_code==200
    q=quote.json()
    registration=dict(schema_version='ln_church.task_offer_registration_request.v1814',
        registration_profile='STRUCTURED_RESPONSE_V3',quote_id=q['quote_id'],quote_token=q['quote_token'],
        confirmed_preview_revision=q['preview']['preview_revision'])
    result=requests.post(origin+'/api/bazaar/task-offers',json=registration,timeout=10)
    assert result.status_code==201
    return q['reservations'][0]['task_id']


def register_followup_blind(origin, study_id, disclosed_id):
    token=secrets.token_hex(32)
    selections=[{'reservation_key':'later-b','kind':'BLIND',
        'participation':{'mode':'EXCLUDE','source_task_id':disclosed_id}}]
    request=dict(schema_version='ln_church.aps_prepare_request.v1',
        preparation_key='sdk-later-'+secrets.token_hex(12),preparation_token=token,
        target={'name':'Synthetic Service','url':'https://service.example/'},
        usage_input={'purpose':'','must':'','volume':'','outcome':''},
        private_reference_items=[],selections=selections,source_study_id=study_id)
    result=requests.post(origin+'/api/agent/aps/preparations',json=request,timeout=10)
    assert result.status_code==202
    preparation_id=result.json()['preparation_id']
    tick(origin,repeat=5)
    preview=requests.post(origin+'/api/agent/aps/preparations/read',json={
        'schema_version':'ln_church.aps_preparation_read.v1','preparation_id':preparation_id,
        'preparation_token':token},timeout=10)
    assert preview.status_code==200 and preview.json()['state']=='READY'
    result=requests.post(origin+'/api/agent/aps/quotes',json={
        'schema_version':'ln_church.aps_quote_request.v1','preparation_id':preparation_id,
        'preparation_token':token,'preview_revision':preview.json()['preview']['preview_revision'],
        'plan_id':'C5','selections':selections,'profile_selected':False,'source_study_id':study_id},timeout=10)
    assert result.status_code==200
    quote=result.json()
    result=requests.post(origin+'/api/bazaar/task-offers',json={
        'schema_version':'ln_church.task_offer_registration_request.v1814',
        'registration_profile':'APS_ORDER_V1','quote_id':quote['quote_id'],'quote_token':quote['quote_token'],
        'confirmed_preview_revision':quote['preview']['preview_revision']},timeout=10)
    assert result.status_code==201
    return quote['reservations'][0]['task_id']


def test_actual_b3_python_and_mcp_flow(venue, tmp_path, monkeypatch):
    origin, state = venue
    exchange = LocalExchange(origin)
    transport = StructuredResponseTransport(exchange=exchange)
    client = StructuredResponseClient(transport=transport)
    page = client.list_tasks()
    assert len(page.tasks)==1 and page.tasks[0].supported
    task = page.tasks[0]
    assert task.aps_kind=='BLIND' and task.context_id is not None
    assert task.task_definition_digest=='1d86750f0fdf7421553c230d45b6dc3f687cb2710010b77f521adf5c6721a7b6'
    alias = task.context_id
    # Actual Claim accepted, response lost, read-only recovery of the saved key.
    exchange.lose_claim = True
    with pytest.raises(StructuredResponseError) as lost:
        client.claim(task.task_id,'sdk-isolated',wallet(1),'claim-primary',journal_directory=tmp_path)
    assert lost.value.code=='CLAIM_OUTCOME_UNKNOWN', [(x['method'],x['path'],x.get('http_status'),x.get('response_keys')) for x in exchange.calls]
    journal=StructuredResponseJournal.open(tmp_path,lost.value.journal_handle)
    credential=client.recover_claim(journal=journal)
    assert exchange.calls[-1]['recovery_read']=='1'
    assert credential.context_id==alias
    context=client.get_context(journal=journal)
    assert context.context_id==alias
    frozen=client.prepare_answer(journal=journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(task))
    exchange.lose_completion=True
    assert client.submit(journal=journal).state=='accepted'
    status=client.get_submission_status(journal=journal)
    assert status.quality['state']=='PENDING' and status.context_id==alias
    token=credential._claim_token_value()
    assert token not in json.dumps(credential.model_dump()) and token not in repr(journal)
    # Actual Backend rejects different bytes under the accepted submission ID.
    changed=frozen.report;changed['items'][0]['reason']='A replacement after receipt.'
    response=requests.post(origin+c.task_completion_path(task.task_id),data=c.canonical_bytes(changed),
        headers={'Content-Type':'application/json','X-LN-Task-Claim-Token':token,
                 'Idempotency-Key':frozen.report['submission_id']},timeout=10)
    assert response.status_code==409
    with pytest.raises(JournalError):
        client.prepare_answer(journal=journal,shared_assumptions={'must':'','volume':'','outcome':''},
            items=[dict(a,reason='Replacement') for a in answers(task)],correction=True)
    # Fill the real C5 B Task; evaluation/closure publishes its dependent D.
    for n in range(2,6):
        op=client.claim(task.task_id,'sdk-isolated',wallet(n),'claim-b-'+str(n),journal_directory=tmp_path)
        client.prepare_answer(journal=op.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(task))
        assert client.submit(journal=op.journal).state=='accepted'
    tick(origin,60001,repeat=10)
    assert client.get_task(task.task_id).status=='CLOSED'
    reopened=StructuredResponseJournal.open(tmp_path,journal.handle)
    before=len(exchange.calls)
    assert client.recover_completion(journal=reopened).state=='accepted'
    assert all(call['method']=='GET' for call in exchange.calls[before:])
    assert reopened.load_report().canonical_bytes==frozen.canonical_bytes
    disclosed=next(t for t in client.list_tasks().tasks if t.aps_kind=='DISCLOSED')
    assert disclosed.context_id!=alias
    for n in range(1,6):
        op=client.claim(disclosed.task_id,'sdk-isolated',wallet(n),'claim-d-'+str(n),journal_directory=tmp_path)
        client.prepare_answer(journal=op.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(disclosed))
        assert client.submit(journal=op.journal).state=='accepted'
    tick(origin,60001,repeat=10)
    assert client.get_task(disclosed.task_id).status=='CLOSED'
    # Fixture requester registration creates a custom Task, no requester SDK added.
    custom_id=register_custom(origin)
    custom=client.get_task(custom_id)
    op=client.claim(custom_id,'sdk-isolated',wallet(20),'custom-structure',journal_directory=tmp_path)
    first=client.prepare_answer(journal=op.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(custom))
    exchange.corrupt_completion=True
    assert client.submit(journal=op.journal).state=='rejected'
    corrected=client.prepare_answer(journal=op.journal,shared_assumptions={'must':'','volume':'','outcome':''},
        items=answers(custom),correction=True)
    assert corrected.report['submission_id']!=first.report['submission_id']
    assert client.submit(journal=op.journal).state=='accepted'
    abandoned=client.claim(custom_id,'sdk-isolated',wallet(21),'custom-abandon',journal_directory=tmp_path)
    assert client.abandon(journal=abandoned.journal,idempotency_key='abandon-key')['state']=='abandoned'
    # MCP invokes the same actual API/client with an independently saved journal.
    from ln_church_agent.integrations import mcp_structured_response as m
    monkeypatch.setattr(m,'StructuredResponseClient',lambda:StructuredResponseClient(transport=transport))
    monkeypatch.setattr(m,'_directory',lambda:tmp_path)
    class Registry:
        def __init__(self):self.tools={}
        def tool(self):
            def save(f):self.tools[f.__name__]=f;return f
            return save
    registry=Registry();m.register_tools(registry);ops=registry.tools
    assert not ops['structured_response_get_task'](custom_id)['read_only']
    selected=ops['structured_response_claim'](custom_id,'mcp-isolated',wallet(22),'mcp-live')
    handle=selected['journal_handle']
    assert ops['structured_response_recover_claim'](handle)['execution_id']==selected['claim']['execution_id']
    assert ops['structured_response_get_context'](handle)['context_id'] is None
    assert ops['structured_response_prepare_answer'](handle,{'must':'','volume':'','outcome':''},answers(custom))['state']=='prepared'
    assert ops['structured_response_submit'](handle)['state']=='accepted'
    assert ops['structured_response_recover_completion'](handle)['state']=='accepted'
    assert ops['structured_response_get_submission_status'](handle)['report']['task_id']==custom_id
    assert 'claim_token' not in json.dumps(selected)
    # Required profile non-disclosures, optional model omission, same client.
    tick(origin,604860000,repeat=12)
    profile=next(t for t in client.list_tasks().tasks if t.model_dump().get('aps_kind')=='PROFILE' and t.status=='OPEN')
    profile_op=client.claim(profile.task_id,'sdk-isolated',wallet(1),'profile-live',journal_directory=tmp_path)
    profile_report=client.prepare_answer(journal=profile_op.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(profile,profile=True))
    assert len(profile_report.report['items'])==4
    assert client.submit(journal=profile_op.journal).state=='accepted'
    tick(origin,60001,repeat=10)
    result=client.get_submission_status(journal=profile_op.journal)
    assert result.entitlement['amount_atomic']=='150000' and result.payout['state']!='paid_confirmed'
    later_id=register_followup_blind(origin,state['quote']['study_id'],disclosed.task_id)
    later=client.get_task(later_id)
    assert later.participation=={'mode':'EXCLUDE','source_task_id':None,'source_visibility':'withheld_for_blind'}
    assert later.supported and later.context_id!=disclosed.context_id
    later_op=client.claim(later_id,'sdk-isolated',wallet(30),'later-blind',journal_directory=tmp_path)
    later_frozen=client.prepare_answer(journal=later_op.journal,shared_assumptions={'must':'','volume':'','outcome':''},items=answers(later))
    assert client.submit(journal=later_op.journal).state=='accepted'
    tick(origin,604860000,repeat=12)
    assert client.get_task(later_id).status=='CLOSED'
    later_journal=StructuredResponseJournal.open(tmp_path,later_op.journal.handle)
    assert client.recover_completion(journal=later_journal).state=='accepted'
    assert later_journal.load_report().canonical_bytes==later_frozen.canonical_bytes
    # Claim deadline has passed: receipt reads preserve original alias/bytes.
    assert client.recover_completion(journal=reopened).state=='accepted'
    assert reopened.load_report().report_sha256==frozen.report_sha256
    future=task.model_dump();future['task_definition_version']='99.0.0'
    assert not StructuredResponseTask(future).supported
    posted=[call for call in exchange.calls if call['path']==c.task_completion_path(task.task_id)]
    assert all(call['key']==frozen.report['submission_id'] and call['body']==frozen.canonical_bytes for call in posted[:1])
    # Evidence records public identities/hashes/counters, never tokens or raw reports.
    destination=os.environ.get('LN_CHURCH_B3_SDK_EVIDENCE')
    if destination:
        Path(destination).write_text(json.dumps({'result':'PASS','backend_commit':'be97c85305fc204021fe14399bc98b7b6cafc15c',
            'transport':'test-only pinned loopback','substitutions':'B3 controlled providers/storage/chain/signature; settlement pending',
            'operations':list(ops),'http_exchanges':len(exchange.calls),
            'original_report_sha256':frozen.report_sha256,'profile_optional_model':'OMITTED',
            'actual_followup_blind_source':'EXCLUDE / NULL / WITHHELD_FOR_BLIND',
            'profile_normal_amount_atomic':result.entitlement['amount_atomic'],
            'real_provider_or_assets':False},indent=2)+'\n')
