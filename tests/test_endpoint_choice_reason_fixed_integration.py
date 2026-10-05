"""Actual fixed Hondo c1 business adapters + SDK, with synthetic provider/storage I/O."""
import json
import pytest
from jsonschema import Draft202012Validator
from test_offer_registration import bridge,client,signed,signature,request,SEED
from ln_church_agent import endpoint_choice_reason_contract as c
from ln_church_agent.endpoint_choice_reason_client import AgentEndpointChoiceReasonClient
from ln_church_agent.endpoint_choice_reason_journal import EndpointChoiceJournal
from ln_church_agent.endpoint_choice_reason_transport import EndpointChoiceTransport
from ln_church_agent.endpoint_choice_reason_requester import EndpointChoiceRequesterClient
from ln_church_agent.offer_registration import OfferRegistrationClient


@pytest.mark.parametrize('version',['v1','v2'])
def test_fixed_pack_worker_requester_round_trip_zero_and_retention(tmp_path,bridge,version):
    req=client(bridge);op=signed(req,"endpoint_choice_reason."+version);registration=req.submit_registration(op);task_id=registration['task_id']
    worker=AgentEndpointChoiceReasonClient(transport=EndpointChoiceTransport(exchange=bridge, version=version), version=version)
    task=worker.get_task(task_id)
    assert task.task_definition_digest==c.load_contract_pack(version)['manifest']['task_definition_digest']
    assert task.successful_claims_lifetime==0 and task.pending_result_count==0
    tmp_path.chmod(0o700)
    j=EndpointChoiceJournal(tmp_path,task_id=task_id,agent_id='fixture',reward_address=op.payer,idempotency_key='worker-claim', version=version)
    credential=worker.claim_task(journal=j)
    report=worker.prepare_answer(journal=j,selected_candidate_id='a',answer_reason='  It fits the stated API need.\n日本語 preserved  ',submission_id='sub_'+'c'*32)
    receipt=worker.complete_task(journal=j)
    saved=worker.get_submission_status(journal=j)
    assert saved.evaluation.q is None and saved.evaluation.applied_coefficient is None
    assert saved.answer_reason==report.report.answer_reason
    bridge.send({'control':'evaluate','task':task_id,'execution':credential.execution_id})
    saved=worker.get_submission_status(journal=j)
    assert saved.evaluation.q=='0' and saved.evaluation.applied_coefficient=='0'
    assert saved.payout.state=='not_applicable' and saved.payout.confirmed_paid_amount_atomic=='0'
    assert saved.correct_candidate_ids is None
    reopened=EndpointChoiceJournal(tmp_path,task_id=task_id,agent_id='fixture',reward_address=op.payer,idempotency_key='worker-claim', version=version)
    calls=len(bridge.calls);worker.recover_completion(journal=reopened)
    assert all(call[0]=='GET' for call in bridge.calls[calls:])
    owner=EndpointChoiceRequesterClient(transport=EndpointChoiceTransport(exchange=bridge, version=version),wall_time=lambda:bridge.send({'control':'counts'})['now']/1000)
    proof=owner.get_results_challenge(task_id,op.payer).sign(signature)
    view=owner.read_results(proof)
    assert view.registration.candidates[0].description_state=='RETAINED'
    assert not worker.get_public_results(task_id).rows
    bridge.send({'control':'configure','advance':604800001 if version=='v2' else 172800001})
    public=worker.get_public_results(task_id)
    assert public.answer_acceptance_closed_at is not None and len(public.rows)==1 and public.rows[0].evaluation.q=='0'
    bridge.send({'control':'configure','advance':2592000001})
    assert bridge.send({'control':'delete-descriptions','task':task_id})['deleted']
    proof=owner.get_results_challenge(task_id,op.payer).sign(signature,now=bridge.send({'control':'counts'})['now']/1000)
    deleted=owner.read_results(proof)
    assert deleted.registration.candidates[0].description_state=='DELETED'
    assert deleted.registration.candidates[0].evaluator_description is None
    proof=req.get_registration_challenge(op.task_type,op.operation_ref,op.payer).sign(signature,now=bridge.send({'control':'counts'})['now']/1000)
    assert req.read_registration(proof).result==registration
    assert bridge.send({'control':'counts'})['settles']==1
    # Check actual SDK requests against the fixed normative wire, not synthetic replacements.
    wire=json.loads(c.load_contract_pack(version)['resources']['wire-contract.json'])
    names={'/claim':'claim_request','/completion':'completion','/challenge':'owner_challenge_request','/read':'owner_read_request'}
    for method,path,_,headers,body in bridge.calls:
        if method!='POST' or 'registration-recovery' in path:continue
        name='registration' if path=='/api/bazaar/task-offers' else next((v for k,v in names.items() if path.endswith(k)),None)
        if name:Draft202012Validator(wire['$defs'][name]).validate(json.loads(body))


_REWARD_VECTORS=json.loads(c.load_contract_pack()['resources']['semantic-fixtures.json'])['reward_vectors']

@pytest.mark.parametrize('vector',_REWARD_VECTORS,ids=lambda v:v['q'])
@pytest.mark.parametrize('correct',[True,False])
def test_normative_reward_vectors_from_fixed_backend(tmp_path,bridge,vector,correct):
    from decimal import Decimal
    from ln_church_agent.crypto.evm import LocalKeyAdapter
    body=request();body['candidates'].append(dict(candidate_id='b',url='https://example.org/',evaluator_description='Other synthetic candidate'))
    req=client(bridge);op=req.prepare_registration(body).sign(LocalKeyAdapter(SEED))
    task_id=req.submit_registration(op)['task_id']
    worker=AgentEndpointChoiceReasonClient(transport=EndpointChoiceTransport(exchange=bridge, version='v1'), version='v1')
    tmp_path.chmod(0o700)
    journal=EndpointChoiceJournal(tmp_path,task_id=task_id,agent_id='fixture',reward_address=op.payer,idempotency_key='vector-claim', version='v1')
    credential=worker.claim_task(journal=journal)
    worker.prepare_answer(journal=journal,selected_candidate_id='a' if correct else 'b',answer_reason='Synthetic reason.',submission_id='sub_'+'d'*32)
    worker.complete_task(journal=journal)
    bridge.send({'control':'evaluate','task':task_id,'execution':credential.execution_id,'q':vector['q']})
    result=worker.get_submission_status(journal=journal)
    assert Decimal(result.evaluation.q)==Decimal(vector['q'])
    assert result.evaluation.is_correct is correct
    assert result.evaluation.approved_amount_atomic==vector['correct_atomic' if correct else 'incorrect_atomic']
