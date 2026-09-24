"""I21-B: provider metadata removed only after known-condition validation."""
import base64
import copy
import json
import pytest
from test_v1_18_5_paid_service_trial_accepted_address import address_lane, run_and_check, wire, wire_v2
from ln_church_agent.paid_service_trial_network import PaidTrialHTTPResponse


def add_extensions(lane, extension, location='envelope'):
    fetch=lane.http.fetch
    def wrapped(request,*,payment_signature=None):
        response=fetch(request,payment_signature=payment_signature)
        if payment_signature is not None:return response
        envelope=json.loads(base64.b64decode(response.headers[0][1]))
        body=json.loads(response.body)
        for value in (envelope,body):
            target=value if location=='envelope' else value['accepts'][0]
            target['extensions']=copy.deepcopy(extension)
        return PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',base64.b64encode(json.dumps(envelope).encode()).decode())],json.dumps(body).encode())
    lane.http.fetch=wrapped


@pytest.mark.parametrize('location',['envelope','condition'])
@pytest.mark.parametrize('metadata',['empty','bazaar','description'])
def test_metadata_normal_executor_report_and_resume(address_lane,location,metadata):
    lane=address_lane
    extension={} if metadata=='empty' else {'catalog':{'description':'Public discovery metadata'}}
    if metadata=='bazaar':
        extension={'bazaar':{'info':{'input':{'type':'http','method':lane.method},
            'output':{'type':'json','example':{'amount':'product-data'}}},
            'schema':{'type':'object','properties':{'input':{'type':'object'}}}}}
    add_extensions(lane,extension,location)
    actual=run_and_check(lane,'issue21-'+metadata+'-'+location)
    assert 'extensions' not in actual and 'extensions' not in actual['accepted']


@pytest.mark.parametrize('extension',[
    {'bazaar':{'info':{'amount':'999'}}},
    {'bazaar':{'parameters':{'payTo':'0x'+'ab'*20}}},
    {'bazaar':{'requirements':{'network':'eip155:1'}}},
    {'bazaar':{'domain':{'name':'Other','version':'2'}}},
    {'bazaar':{'domain':{'chainId':1}}},
    {'bazaar':{'info':{'extra':{'name':'Other','version':'2'}}}},
    {'bazaar':{'domain':{'verifyingContract':'0x'+'ab'*20}}},
    {'bazaar':{'info':{'maxTimeoutSeconds':1}}},
    {'bazaar':{'info':{'token_address':'bad'}}},
    {'permit2':{}},{'custom':{'assetTransferMethod':'permit2'}},
    {'custom':{'authorization':{}}},{'settlement':{}},
])
def test_metadata_never_hides_payment_contradictions(address_lane,extension):
    lane=address_lane;add_extensions(lane,extension)
    with pytest.raises(ValueError):lane.executor.execute(lane.w.credential,journal=lane.journal)
    assert lane.signer.calls==[] and lane.http.paid==0


def test_metadata_wrong_method_keeps_fixed_request(address_lane):
    lane=address_lane;original=copy.deepcopy(lane.target)
    add_extensions(lane,{'bazaar':{'info':{'input':{'method':'POST' if lane.method=='GET' else 'GET'}}}})
    with pytest.raises(ValueError):lane.executor.execute(lane.w.credential,journal=lane.journal)
    assert lane.target==original and not lane.signer.calls and lane.http.paid==0


@pytest.fixture(autouse=True)
def extension_evidence(address_lane,record_property):
    yield
    lane=address_lane
    record_property('extension_evidence',json.dumps(dict(version=lane.version,method=lane.method,
        terms_calls=lane.http.unpaid,signer_calls=len(lane.signer.calls),paid_sends=lane.http.paid,
        completion_posts=len(lane.transport.posts),live_payments=0)))
