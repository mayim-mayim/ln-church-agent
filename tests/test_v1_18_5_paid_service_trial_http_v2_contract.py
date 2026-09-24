"""HTTP Wire §2/3 and the exact canonical semantic vectors, not a formal pack."""
import base64
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_account import Account
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.crypto.evm import LocalKeyAdapter
from ln_church_agent.paid_service_trial_models import (
    PaidServiceTrialClaimV2, PaidServiceTrialTaskV2, PaidServiceTrialClaim,
    FrozenPaidServiceTrialReport, PurchaseTerms,
)
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_transport import (
    PaidServiceTrialTransport, PaidServiceTrialRawResponse, PaidServiceTrialAPIError,
    PaidServiceTrialTransportError,
)

FIXTURE = Path(__file__).parent/'fixtures/v185-paid-service-trial-v2/semantic-contract.json'
GOLDEN = json.loads(FIXTURE.read_text())['http_golden_vectors']


@pytest.mark.parametrize('case',GOLDEN['valid_body_vectors'],ids=lambda x:x['id'])
def test_body_golden_bytes(case):
    actual=c.v2_canonical_body(case['input']).encode()
    assert actual==case['canonical'].encode()
    assert len(actual)==case['canonical_utf8_bytes']
    assert hashlib.sha256(actual).hexdigest()==case['body_sha256']


@pytest.mark.parametrize('case',GOLDEN['request_binding_vectors'],ids=lambda x:x['id'])
def test_request_and_purchase_golden(case):
    request=case['request']
    actual=c.prepare_request(dict(method=request['method'],url=request['url'],body=case['source_body_input']))
    assert actual==request
    assert c.v2_jcs_bytes(actual)==case['canonical_request'].encode()
    assert c.v2_digest(actual)==case['request_digest']
    binding=case['purchase_binding']
    terms={k:binding[k] for k in ('x402_version','authorization_method','requirements')}
    assert c.v2_jcs_bytes(binding)==case['canonical_purchase_binding'].encode()
    assert c.purchase_terms_digest(actual,terms)==case['purchase_terms_digest']
    assert c.v2_digest({k:v for k,v in binding.items() if k!='resource_url'})!=case['purchase_terms_digest']


@pytest.mark.parametrize('case',GOLDEN['invalid_body_vectors'],ids=lambda x:x['id'])
def test_invalid_golden(case):
    raw=bytes.fromhex(case['input_utf8_hex']) if 'input_utf8_hex' in case else case['input'].encode()
    with pytest.raises(ValueError):c.v2_decode_json(raw,16384)


@pytest.mark.parametrize('text',['',' ','NaN','Infinity','-Infinity','\ufeffnull',
    '{"a":1,"a":2}','9007199254740993','-9007199254740993','9007199254740991.9',
    '9007199254740992e-0','1e9999','['*65+'0'+']'*65])
def test_invalid_before_request_preparation(text):
    with pytest.raises(ValueError):c.prepare_request(dict(method='POST',url='https://example.com/paid',body=text))


def test_inclusive_depth_bytes_and_scalar_boundaries():
    for text in ['['*64+'0'+']'*64,'true','false','null','""','9007199254740991','-9007199254740991',
                 '1e-6','1e-7','5e-324','1.2345','-0.0']:
        assert c.v2_canonical_body(text)
    value='"'+'x'*16382+'"'
    assert len(c.v2_canonical_body(value).encode())==16384
    with pytest.raises(ValueError):c.v2_canonical_body(value+' ')
    with pytest.raises(ValueError):c.v2_canonical_body('"'+'x'*16383+'"')
    assert c.v2_canonical_body('1e-6')=='0.000001'
    assert c.v2_canonical_body('-0.0')=='0'
    assert c.v2_canonical_bytes('x'*65534)==b'"'+b'x'*65534+b'"'
    with pytest.raises(ValueError):c.v2_canonical_bytes('x'*65535)


def test_outer_unicode_is_not_normalized():
    request=c.prepare_request(dict(method='POST',url='https://example.com/paid',body='{"e\\u0301":1}'))
    assert 'e\u0301' in c.v2_jcs_bytes(request).decode()
    other=c.prepare_request(dict(method='POST',url=request['url'],body='{"é":1}'))
    assert c.v2_digest(request)!=c.v2_digest(other)


@pytest.fixture
def wire_v2(monkeypatch):
    signer=LocalKeyAdapter(Account.create().key.hex())
    terms={'x402_version':2,'authorization_method':'EIP-3009','requirements':{
        'scheme':'exact','network':c.NETWORK,'asset':c.ASSET,'amount':'1000',
        'payTo':'0x'+'12'*20,'maxTimeoutSeconds':900,'extra':{'name':'USD Coin','version':'2'}}}
    reward={'network':c.NETWORK,'asset':'USDC','asset_address':c.ASSET,'amount_atomic':'20000'}
    request=c.prepare_request(dict(method='POST',url='https://seller.example.com/paid?x=1',body='{"e\\u0301":"😀","x":1.25}'))
    public=dict(request=request,request_digest=c.v2_digest(request),purchase_terms=terms,
        purchase_terms_digest=c.purchase_terms_digest(request,terms),plan_id='C40',
        registration_amount_atomic='1000000',capacity_total=40,repeat_policy='ALLOW_REPEAT',reward=reward)
    # Deliberately test-only. No generated six-artifact directory is installed.
    definition_digest='d'*64
    monkeypatch.setattr(c,'load_contract_bundle',lambda version='v1':{'manifest':{'task_definition_digest':definition_digest}})
    task=dict(public,schema_version=c.V2_TASK_SCHEMA_VERSION,task_id='Case.Task~X',task_type=c.V2_TASK_TYPE,
        task_definition_version='2.0.0',task_definition_digest=definition_digest,terms_digest=c.v2_digest(public),
        status='OPEN',published_at='2026-09-21T00:00:00.000Z',listing_ends_at='2026-09-23T00:00:00.000Z',
        capacity_reserved=0,capacity_consumed=0,capacity_available=40,definition_url=c.V2_DEFINITION_URL,
        summary_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/Case.Task~X/summary',
        results_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/Case.Task~X/execution-summaries')
    claim={k:task[k] for k in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest',
        'request','request_digest','purchase_terms_digest','purchase_terms','repeat_policy','reward')}
    claim.update(schema_version='ln_church.agent_task_claim_response.paid_service_trial.v2',
        execution_id='execution~opaque',claim_token=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='),
        reward_address=signer.address.lower(),reward_address_control_verified=False,
        claim_accepted_at='2026-09-21T00:00:00.000Z',report_deadline='2026-09-21T00:10:00.000Z',
        purchase_block_timestamp_exclusive_min='1789948800')
    return SimpleNamespace(signer=signer,terms=terms,request=request,task=task,claim=claim,
        credential=PaidServiceTrialClaimV2.model_validate(claim),now=1789948802)


def report_for_v2(wire):
    claim=wire.claim
    data={k:claim[k] for k in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest',
        'request_digest','purchase_terms_digest','execution_id')}
    data.update(schema_version='ln_church.task_completion.paid_service_trial.v2',submission_id='sub_'+'a'*32,
        purchase={'network':c.NETWORK,'asset':c.ASSET,'payer':claim['reward_address'],
        'authorization_nonce':'0x'+'ab'*32,'payTo':wire.terms['requirements']['payTo'],
        'amount':'1000','validAfter':'0','validBefore':str(wire.now+300)})
    return FrozenPaidServiceTrialReport.from_dict(data)


def receipt_for_v2(report):
    from test_v1_18_5_paid_service_trial_contract import receipt_for
    result=receipt_for(report);result['schema_version']='ln_church.task_completion_receipt.paid_service_trial.v2'
    return result


def status_for_v2(report):
    from test_v1_18_5_paid_service_trial_contract import status_for
    result=status_for(report);result['schema_version']='ln_church.task_submission_status.paid_service_trial.v2'
    return result


class V2TaskTransport:
    def __init__(self,wire):
        self.wire=wire;self.posts=[];self.reads=0;self.accepted=None;self.lose_response=False;self.fail_posts=False;self.conflict=False;self.events=[]
    def close(self):pass
    def post_completion_bytes(self,task,token,submission,body,**kwargs):
        assert kwargs['version']=='v2'
        self.events.append('POST');self.posts.append((body,kwargs))
        if self.conflict:raise PaidServiceTrialAPIError('report_conflict',status_code=409)
        if self.fail_posts:raise PaidServiceTrialTransportError('TIMEOUT')
        self.accepted=FrozenPaidServiceTrialReport(body)
        if self.lose_response:raise PaidServiceTrialTransportError('TIMEOUT')
        return receipt_for_v2(self.accepted)
    def get_submission_status(self,*args,**kwargs):
        assert kwargs['version']=='v2';self.reads+=1;self.events.append('GET')
        if not self.accepted:raise PaidServiceTrialAPIError('not_found',status_code=404)
        return status_for_v2(self.accepted)


def test_default_v2_and_shared_claim_request(wire_v2):
    wire=wire_v2;seen=[]
    def exchange(method,path,query,headers,body,timeout):
        seen.append((method,path,query,headers,body))
        value=wire.task
        if path.endswith('/claim'):value=wire.claim
        if path=='/api/agent/tasks':value={'schema_version':'ln_church.agent_task_page.paid_service_trial.v2','tasks':[wire.task],'next_cursor':None}
        return PaidServiceTrialRawResponse(200,{},json.dumps(value).encode())
    client=PaidServiceTrialTaskClient(transport=PaidServiceTrialTransport(exchange=exchange))
    assert client.version=='v2'
    client.list_tasks();client.get_task(wire.task['task_id']);claim=client.claim_task(wire.task['task_id'],'agent',wire.signer.address,idempotency_key='claim')
    assert seen[0][2]=='task_type=paid_service_trial.v2&task_schema_version=ln_church.agent_task.paid_service_trial.v2&limit=25'
    assert json.loads(seen[2][4])['schema_version']=='ln_church.agent_task_claim_request.v1'
    assert claim.request.model_dump()==wire.request
    assert 'claim_token' not in claim.model_dump()
    with pytest.raises(ValueError):PaidServiceTrialClaim.model_validate(wire.claim)


@pytest.mark.parametrize('edit',[{'request':None},{'request_digest':'a'*64},{'purchase_terms_digest':'a'*64},
    {'task_type':c.TASK_TYPE},{'task_definition_version':'1.0.0'},{'schema_version':c.TASK_SCHEMA_VERSION},
    {'endpoint':'https://seller.example.com/paid'},{'extra':1}])
def test_closed_v2_binding_rejects_mixed(wire_v2,edit):
    with pytest.raises(ValueError):PaidServiceTrialTaskV2.model_validate(dict(wire_v2.task,**edit))


def test_request_rejects_noncanonical_or_changed_body(wire_v2):
    for edit in [{'body':'{}'},{'body_sha256':'a'*64},{'body':' '+wire_v2.request['body']},
                 {'method':'GET'},{'content_type':'text/plain'},{'unknown':None}]:
        with pytest.raises(ValueError):c.validate_request(dict(wire_v2.request,**edit))


@pytest.mark.parametrize('reason',sorted(c.V2_TERMS_REASONS))
def test_v2_finite_error(reason):
    value=dict(schema_version='ln_church.task_error.paid_service_trial.v2',code='unsupported_purchase_terms',
        message='raw provider text must not escape',request_id='id',reason=reason)
    transport=PaidServiceTrialTransport(exchange=lambda *args:PaidServiceTrialRawResponse(400,{},json.dumps(value).encode()))
    with pytest.raises(PaidServiceTrialAPIError) as caught:transport.list_tasks()
    assert caught.value.reason==reason and 'raw provider' not in str(caught.value)


def test_error_reason_closed():
    for code,reason in [('unsupported_purchase_terms',None),('unsupported_purchase_terms','provider says secret'),('invalid_request','expected_402')]:
        value=dict(schema_version='ln_church.task_error.paid_service_trial.v2',code=code,message='x',request_id='id',reason=reason)
        transport=PaidServiceTrialTransport(exchange=lambda *args:PaidServiceTrialRawResponse(400,{},json.dumps(value).encode()))
        with pytest.raises(PaidServiceTrialTransportError):transport.list_tasks()


@pytest.mark.parametrize('body',[
    '1e-9999999999999999999','0e9999999999999999999',
    '-1e-9999999999999999999','-0.00e+9999999999999999999',
    '1e-'+'9'*16381,'0e'+'9'*16382,
])
def test_c2_valid_extreme_exponent_public_preparation(body):
    from ln_church_agent import prepare_paid_service_request
    request=prepare_paid_service_request(dict(method='POST',url='https://seller.example.com/paid',body=body))
    assert request['body']=='0'
    assert request['body_sha256']==hashlib.sha256(b'0').hexdigest()
    assert c.validate_request(request)==request


@pytest.mark.parametrize('body',[
    '1e9999999999999999999','-1e9999999999999999999',
    '9007199254740993e0','90071992547409920e-1',
    '9007199254740991.5','-9007199254740991.5',
])
def test_c2_extreme_exponent_and_unsafe_integers_still_rejected(body):
    with pytest.raises(ValueError):c.prepare_request(dict(method='POST',url='https://seller.example.com/paid',body=body))


@pytest.mark.parametrize('body,canonical',[
    ('90071992547409910e-1','9007199254740991'),
    ('9007199254740991'+'0'*5000+'e-5000','9007199254740991'),
    ('0.'+'0'*5000+'1e5001','1'),('1e'+'0'*5000+'-1',None),
])
def test_c2_lexical_integer_boundaries(body,canonical):
    if canonical is None:
        with pytest.raises(ValueError):c.v2_canonical_body(body)
    else:assert c.v2_canonical_body(body)==canonical


@pytest.mark.parametrize('url,expected',[
    ('https://SELLER.example.com:443/paid','https://seller.example.com/paid'),
    ('https://SELLER.example.com:443','https://seller.example.com/'),
    ('HTTPS://SELLER.example.com:443/paid?x=1&x=2','https://seller.example.com/paid?x=1&x=2'),
    ('https://SELLER.example.com:443/paid?','https://seller.example.com/paid?'),
])
def test_c2_input_url_normalizes_but_frozen_request_stays_strict(url,expected):
    request=c.prepare_request(dict(method='GET',url=url,body=None))
    assert request['url']==expected
    assert c.validate_request(request)==request
    replaced=dict(request,url=url)
    with pytest.raises(ValueError):c.validate_request(replaced)
    assert replaced['url']==url


@pytest.mark.parametrize('url',[
    'http://SELLER.example.com:443/paid','https://SELLER.example.com:444/paid',
    'https://SELLER.example.com:0/paid','https://user@SELLER.example.com/paid',
    'https://SELLER.example.com/paid#fragment','https://SELLER.example.com/paid#',
    'https://127.0.0.1:443/paid','https://LOCALHOST:443/paid',
    'https://SELLER.example.com/paid?token=secret','https://SELLER.example.com/../paid',
    'https://SELLER.example.com/pa\nid','https://SELLER.example.com\\paid',
])
def test_c2_url_preparation_retains_public_and_secret_policy(url):
    with pytest.raises(ValueError):c.prepare_request(dict(method='GET',url=url,body=None))
