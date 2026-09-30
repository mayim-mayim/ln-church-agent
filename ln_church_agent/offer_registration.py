"""Explicit A/B paid registration and same-operation read recovery.

Payment attempts and read proofs are private, memory-only capabilities. No
implicit purchase, signer, durable payment store, or business retry is installed.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import re
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from functools import wraps

from . import endpoint_choice_reason_contract as c
from .endpoint_choice_reason_requester import prepare_registration, EndpointChoiceRegistrationInput
from .immediate_visit_transport import ImmediateVisitTransport, ImmediateVisitRawResponse
from .immediate_visit_versions import load_v2_pack, validate_version
from .paid_service_trial_contract import decode_base64_object
from .crypto.evm import validate_eip3009_payload

PATH = '/api/bazaar/task-offers'
READ_PATH = '/api/agent/task-offer-registration-recovery/'
PROFILES = {c.TASK_TYPE: 'V189_ENDPOINT_CHOICE_REASON',
            'immediate_http_visit.v1': 'V183_IMMEDIATE_VISIT',
            'immediate_http_visit.v2': 'V183_IMMEDIATE_VISIT'}
PAYMENT_STATES = {'UNPAID','AUTHORIZATION_BOUND','SETTLING','CONFIRMING',
    'ATTEMPT_REVERTED_AUTHORIZATION_LIVE','UNKNOWN','UNKNOWN_EXHAUSTED','CONFIRMED','FAILED','EXPIRED_UNPAID'}
DOMAIN = dict(name='LNChurch Registration Recovery', version='1', chainId=8453)
FIELDS = [('audience','string'),('action','string'),('profile','string'),('operationRef','string'),
          ('payer','address'),('nonce','bytes32'),('issuedAt','uint256'),('expiresAt','uint256')]
TYPES = {'EIP712Domain': [dict(name=k,type=v) for k,v in [('name','string'),('version','string'),('chainId','uint256')]],
         'OfferRegistrationRead': [dict(name=k,type=v) for k,v in FIELDS]}


class OfferRegistrationError(Exception):
    def __init__(self, code, *, status_code=None):
        safe = {'REQUEST_INVALID','RESPONSE_INVALID','TRANSPORT_ERROR','CLIENT_CLOSED',
                'REGISTRATION_OUTCOME_UNKNOWN','REGISTRATION_REJECTED','SIGNING_FAILED',
                'READ_PROOF_EXPIRED','READ_PROOF_INVALID','registration_recovery_unavailable',
                'invalid_recovery_proof','recovery_proof_expired','recovery_temporarily_unavailable','invalid_request'}
        self.code = code if code in safe else 'RESPONSE_INVALID'
        self.status_code = status_code
        super().__init__(self.code)


def boundary(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        error = None
        try:
            return fn(*args, **kwargs)
        except OfferRegistrationError as exc:
            error = OfferRegistrationError(exc.code, status_code=exc.status_code)
        except Exception:
            error = OfferRegistrationError('REQUEST_INVALID')
        raise error
    return call


def reference(value):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}',value) is None:
        raise ValueError('Invalid reference.')
    return value


def family(task_type):
    if task_type not in PROFILES: raise ValueError('Unsupported registration family.')
    return PROFILES[task_type]


def plan(task_type, plan_id):
    if task_type == c.TASK_TYPE: return c.PLANS[plan_id]
    family(task_type)
    return {'C50':('1000000',50),'C500':('10000000',500),'C5000':('100000000',5000)}[plan_id]


def _request(value):
    if isinstance(value, EndpointChoiceRegistrationInput): value = value._private_payload()
    if type(value) is not dict: raise ValueError('Invalid registration.')
    task_type = value.get('task_type'); family(task_type)
    if task_type == c.TASK_TYPE:
        c.load_contract_pack()
        return prepare_registration(value)._private_payload()
    if task_type.endswith('.v2'): load_v2_pack()
    if set(value) != {'task_type','plan_id','repeat_policy','urls'} or value['repeat_policy'] not in ('allow','once_per_endpoint'):
        raise ValueError('Invalid registration.')
    plan(task_type,value['plan_id'])
    if type(value['urls']) is not list or not 1 <= len(value['urls']) <= 10: raise ValueError('Invalid URLs.')
    urls = [c.prepare_url(url) for url in value['urls']]
    if len(set(urls)) != len(urls): raise ValueError('Duplicate URL.')
    return dict(value, urls=urls)


def _requirements(request, value):
    amount,_ = plan(request['task_type'],request['plan_id'])
    if type(value) is not dict or set(value) != {'scheme','network','asset','amount','payTo','maxTimeoutSeconds','extra'}:
        raise ValueError('Invalid payment terms.')
    if (value['scheme'] != 'exact' or value['network'] != 'eip155:8453' or c.address(value['asset']) != c.ASSET
            or value['amount'] != amount or type(value['maxTimeoutSeconds']) is not int or value['maxTimeoutSeconds'] != 300
            or value['extra'] != {'name':'USD Coin','version':'2'}): raise ValueError('Invalid payment terms.')
    c.address(value['payTo'])
    return copy.deepcopy(value)


def _resource(task_type):
    return dict(url=c.PUBLIC_API_ORIGIN+PATH, description=('Register a URL Choice & Reason Task'
                if task_type == c.TASK_TYPE else 'Register an immediate public HTTP visit Task'), mimeType='application/json')


def _operation_ref(task_type, envelope):
    req, auth = envelope['accepted'], envelope['payload']['authorization']
    if type(auth['nonce']) is not str or re.fullmatch(r'0x[0-9a-fA-F]{64}',auth['nonce']) is None: raise ValueError
    g = c.digest(['ln-church/x402-eip3009/v1','eip155:8453',c.address(req['asset']),c.address(auth['from']),auth['nonce'].lower()])
    prefix = 'endpoint-choice-reason-registration' if task_type == c.TASK_TYPE else 'immediate-registration'
    s = hashlib.sha256((prefix+'\0'+g).encode()).hexdigest()
    return s[:8]+'-'+s[8:12]+'-4'+s[13:16]+'-8'+s[17:20]+'-'+s[20:32]


class _Private:
    __slots__ = ()
    def __repr__(self): return self.__class__.__name__+'(<private>)'
    def __reduce_ex__(self, protocol): raise TypeError('Registration capabilities stay in memory.')


class RegistrationQuote(_Private):
    __slots__ = ('_body','_challenge','_lock','_signed','_sign_started')
    def __init__(self, body, challenge):
        self._body, self._challenge = body, c.canonical_bytes(challenge,32768)
        self._lock, self._signed, self._sign_started = threading.Lock(), None, False
    @property
    def payment_terms(self):
        return copy.deepcopy(c.decode_json_object(self._challenge,32768)['accepts'][0])
    @boundary
    def sign(self, signer, *, now=None):
        """Explicit payment authorization; repeated calls return the original attempt."""
        with self._lock:
            if self._signed is not None: return self._signed
            if self._sign_started: raise OfferRegistrationError('SIGNING_FAILED')
            self._sign_started = True
            req = self.payment_terms; t = int(time.time() if now is None else now)
            try:
                payload = signer.generate_eip3009_payload_atomic('USDC',req['amount'],req['payTo'],chain_id=8453,
                    token_address=req['asset'],valid_before=t+300,now=t)
                validate_eip3009_payload(payload,expected_signer=signer.address,chain_id=8453,token_address=req['asset'],
                    asset='USDC',atomic_amount=req['amount'],pay_to=req['payTo'],now=t,max_valid_before=t+300)
                challenge = c.decode_json_object(self._challenge,32768)
                envelope = dict(x402Version=2,resource=challenge['resource'],accepted=req,payload=payload)
                header = base64.b64encode(c.canonical_bytes(envelope,24576)).decode('ascii')
                self._signed = SignedRegistration(self._body,header)
                return self._signed
            except Exception:
                pass
            raise OfferRegistrationError('SIGNING_FAILED')


class SignedRegistration(_Private):
    __slots__ = ('_body','_header','_task_type','_reference','_payer','_lock','_sent','_result')
    def __init__(self, body, header):
        request = _request(c.decode_json_object(body,65536))
        envelope = decode_base64_object(header)
        if set(envelope) != {'x402Version','resource','accepted','payload'} or type(envelope['x402Version']) is not int or envelope['x402Version'] != 2:
            raise ValueError('Invalid original payment.')
        _requirements(request,envelope['accepted'])
        if envelope['resource'] != _resource(request['task_type']): raise ValueError('Invalid payment resource.')
        auth = envelope['payload']['authorization']
        # Validate the original signature at a point within its original window.
        # Expiry never creates a new purchase or prevents read-only recovery.
        a,b = int(c.atomic(auth['validAfter'])),int(c.atomic(auth['validBefore']))
        validate_eip3009_payload(envelope['payload'],expected_signer=auth['from'],chain_id=8453,token_address=c.ASSET,
            asset='USDC',atomic_amount=envelope['accepted']['amount'],pay_to=envelope['accepted']['payTo'],now=a+1,max_valid_before=b)
        self._body, self._header = c.canonical_bytes(request,65536),header
        self._task_type, self._reference = request['task_type'],_operation_ref(request['task_type'],envelope)
        self._payer = c.address(auth['from']); self._lock = threading.Lock(); self._sent = False; self._result = None
    @property
    def operation_ref(self): return self._reference
    @property
    def task_type(self): return self._task_type
    @property
    def profile(self): return family(self._task_type)
    @property
    def payer(self): return self._payer


@dataclass(frozen=True)
class RegistrationReadResult:
    """COMMITTED is the original public snapshot, never current Task state."""
    profile: str
    operation_ref: str
    kind: str
    result: object
    status: object


def _success(value, task_type, operation_ref, request=None):
    fields = {'schema_version','registration_intent_id','task_id','task_type','status','task_url','summary_url',
              'results_url','published_at','listing_ends_at','plan_id','registration_amount_atomic','capacity_total'}
    fields.add('manifest_url' if task_type == c.TASK_TYPE else 'repeat_policy')
    suffix = 'endpoint_choice_reason.v1' if task_type == c.TASK_TYPE else 'immediate_visit.'+task_type.rsplit('.',1)[1]
    if (type(value) is not dict or set(value) != fields or value['schema_version'] != 'ln_church.task_offer_create_response.'+suffix
            or value['registration_intent_id'] != reference(operation_ref) or value['task_type'] != task_type or value['status'] != 'OPEN'):
        raise OfferRegistrationError('RESPONSE_INVALID')
    task_id = c.validate_task_id(value['task_id'])
    amount,capacity = plan(task_type,value['plan_id'])
    if value['registration_amount_atomic'] != amount or type(value['capacity_total']) is not int or value['capacity_total'] != capacity:
        raise OfferRegistrationError('RESPONSE_INVALID')
    if c.parse_timestamp(value['listing_ends_at'])-c.parse_timestamp(value['published_at']) != timedelta(hours=48): raise ValueError
    links = dict(task_url=c.PUBLIC_API_ORIGIN+c.task_detail_path(task_id),
        summary_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/'+task_id+'/summary',
        results_url=c.PUBLIC_API_ORIGIN+c.task_detail_path(task_id)+'/results')
    if task_type != c.TASK_TYPE: links['results_url']=c.PUBLIC_API_ORIGIN+'/agent-taskboard.html?task_id='+task_id+'&view=results'
    if task_type == c.TASK_TYPE: links['manifest_url']=c.PUBLIC_API_ORIGIN+'/agent-task-specs/'+task_type+'/1.0.0/manifest.json'
    if any(value[k] != v for k,v in links.items()): raise OfferRegistrationError('RESPONSE_INVALID')
    if task_type != c.TASK_TYPE and value['repeat_policy'] not in ('allow','once_per_endpoint'): raise ValueError
    if request is not None and (value['plan_id'] != request['plan_id'] or (task_type != c.TASK_TYPE and value['repeat_policy'] != request['repeat_policy'])): raise ValueError
    return copy.deepcopy(value)


def _status(value):
    if (type(value) is not dict or set(value) != {'payment_state','business_commit_state','recovery_mode'}
            or value['payment_state'] not in PAYMENT_STATES or value['business_commit_state'] not in ('PRIVATE','COMMIT_DUE','COMMIT_BLOCKED')
            or value['recovery_mode'] not in ('READBACK_ONLY','TERMINAL_NEW_ATTEMPT_AVAILABLE')): raise OfferRegistrationError('RESPONSE_INVALID')
    return copy.deepcopy(value)


def _challenge(value, task_type, ref, payer, now):
    family(task_type); reference(ref); payer=c.address(payer)
    if type(value) is not dict or set(value) != {'schema_version','challenge_token','typed_data'} or value['schema_version'] != 'ln_church.registration_read_challenge.v1': raise ValueError
    if type(value['challenge_token']) is not str or not value['challenge_token'] or len(value['challenge_token'].encode()) > 8192: raise ValueError
    t=value['typed_data']
    if type(t) is not dict or set(t) != {'domain','types','primaryType','message'} or t['domain'] != DOMAIN or type(t['domain'].get('chainId')) is not int or t['types'] != TYPES or t['primaryType'] != 'OfferRegistrationRead': raise ValueError
    m=t['message']
    if type(m) is not dict or set(m) != {k for k,_ in FIELDS}: raise ValueError
    if (m['audience'] != c.PUBLIC_API_ORIGIN+READ_PATH+'status' or m['action'] != 'read_registration_result'
            or m['profile'] != family(task_type) or m['operationRef'] != ref or m['payer'] != payer
            or type(m['nonce']) is not str or re.fullmatch(r'0x[0-9a-f]{64}',m['nonce']) is None): raise ValueError
    a,b=int(c.atomic(m['issuedAt'])),int(c.atomic(m['expiresAt']))
    if b != a+300 or now<a: raise ValueError
    if now>=b: raise OfferRegistrationError('READ_PROOF_EXPIRED')
    return copy.deepcopy(value)


class RegistrationReadChallenge(_Private):
    __slots__=('_wire','_task_type','_ref','_payer')
    def __init__(self, value, task_type, ref, payer, now):
        self._wire=c.canonical_bytes(_challenge(value,task_type,ref,payer,now),16384)
        self._task_type,self._ref,self._payer=task_type,ref,c.address(payer)
    @boundary
    def sign(self, signer, *, now=None):
        value=_challenge(c.decode_json_object(self._wire,16384),self._task_type,self._ref,self._payer,time.time() if now is None else now)
        signature=signer(copy.deepcopy(value['typed_data']))
        if type(signature) is not str or re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+',signature) is None: raise ValueError
        return RegistrationReadProof(self,signature)


class RegistrationReadProof(_Private):
    __slots__=('_challenge','_signature')
    def __init__(self, challenge, signature): self._challenge,self._signature=challenge,signature
    def _body(self, now):
        ch=self._challenge
        value=_challenge(c.decode_json_object(ch._wire,16384),ch._task_type,ch._ref,ch._payer,now)
        return c.canonical_bytes(dict(value,schema_version='ln_church.registration_read_request.v1',signature=self._signature),32768)


class OfferRegistrationClient:
    """Paid sends are explicit; recovery reads cannot sign or carry payment headers."""
    def __init__(self, *, transport=None, wall_time=time.time):
        if transport is not None and not isinstance(transport,ImmediateVisitTransport): raise ValueError('Invalid registration transport.')
        self._transport=transport or ImmediateVisitTransport(); self._owns=transport is None; self._clock=wall_time
        self._closed=False
    def close(self):
        self._closed=True
        if self._owns:self._transport.close()
    def __enter__(self): return self
    def __exit__(self,*args):self.close()
    def _send(self, path, body, timeout, payment=None):
        if self._closed or self._transport._closed: raise OfferRegistrationError('CLIENT_CLOSED')
        c.positive_bound(timeout,'timeout_seconds')
        headers={'Accept':'application/json','Accept-Encoding':'identity','Content-Type':'application/json; charset=utf-8','User-Agent':'ln-church-agent/1.18.9'}
        if payment is not None:
            if path != PATH: raise ValueError
            headers['PAYMENT-SIGNATURE']=payment
        failed=False
        try: raw=self._transport._exchange('POST',path,None,headers,body,timeout)
        except Exception: failed=True
        if failed: raise OfferRegistrationError('TRANSPORT_ERROR')
        try:
            if not isinstance(raw,ImmediateVisitRawResponse) or type(raw.status_code) is not int: raise ValueError
            hs={}
            for k,v in raw.headers.items():
                if type(k) is not str or type(v) is not str or k.lower() in hs: raise ValueError
                hs[k.lower()]=v
            if sum(len(k)+len(v)+4 for k,v in hs.items())>32768 or hs.get('content-encoding','identity').lower()!='identity': raise ValueError
            value=c.decode_json_object(raw.body,131072)
            return raw.status_code,hs,value
        except Exception: pass
        raise OfferRegistrationError('RESPONSE_INVALID')
    @boundary
    def prepare_registration(self, request, *, timeout_seconds=20.0):
        request=_request(request); body=c.canonical_bytes(request,65536)
        status,headers,value=self._send(PATH,body,timeout_seconds)
        if status != 402: raise OfferRegistrationError('REGISTRATION_REJECTED',status_code=status)
        if (type(value) is not dict or set(value) != {'x402Version','resource','accepts'} or type(value['x402Version']) is not int
            or value['x402Version']!=2 or value['resource']!=_resource(request['task_type']) or type(value['accepts']) is not list
            or len(value['accepts'])!=1 or decode_base64_object(headers['payment-required'])!=value): raise ValueError
        _requirements(request,value['accepts'][0])
        return RegistrationQuote(body,value)
    @boundary
    def restore_registration(self, request, original_payment_header):
        """Use caller-retained original private bytes; never generates an authorization."""
        return SignedRegistration(c.canonical_bytes(_request(request),65536),original_payment_header)
    @boundary
    def submit_registration(self, operation, *, replay=False, timeout_seconds=20.0):
        if not isinstance(operation,SignedRegistration) or type(replay) is not bool: raise ValueError
        with operation._lock:
            if operation._result is not None: return copy.deepcopy(operation._result)
            if operation._sent and not replay: raise OfferRegistrationError('REGISTRATION_OUTCOME_UNKNOWN')
            operation._sent=True
            try:
                code,headers,value=self._send(PATH,operation._body,timeout_seconds,operation._header)
                if code==200:
                    result=_success(value,operation.task_type,operation.operation_ref,c.decode_json_object(operation._body,65536))
                    operation._result=result;return copy.deepcopy(result)
                if code==202:
                    if value.get('registration_intent_id')!=operation.operation_ref: raise ValueError
                    state=_status({k:value[k] for k in ('payment_state','business_commit_state','recovery_mode')})
                    return RegistrationReadResult(operation.profile,operation.operation_ref,'STATUS',None,state)
            except Exception: pass
            # Even a 404, error, or malformed response after dispatch is not a new-purchase permit.
            raise OfferRegistrationError('REGISTRATION_OUTCOME_UNKNOWN')
    @boundary
    def get_registration_challenge(self, task_type, operation_ref, payer, *, timeout_seconds=20.0):
        body=c.canonical_bytes(dict(schema_version='ln_church.registration_read_challenge_request.v1',
            profile=family(task_type),operation_ref=reference(operation_ref),payer=c.address(payer)))
        status,_,value=self._send(READ_PATH+'challenge',body,timeout_seconds)
        self._read_error(status,value)
        return RegistrationReadChallenge(value,task_type,operation_ref,payer,self._clock())
    @staticmethod
    def _read_error(status,value):
        if status==200:return
        allowed={400:{'invalid_request'},401:{'invalid_recovery_proof','recovery_proof_expired'},
                 404:{'registration_recovery_unavailable'},503:{'recovery_temporarily_unavailable'}}
        if set(value)=={'error_code'} and value['error_code'] in allowed.get(status,set()):
            raise OfferRegistrationError(value['error_code'],status_code=status)
        raise OfferRegistrationError('RESPONSE_INVALID',status_code=status)
    @boundary
    def read_registration(self, proof, *, timeout_seconds=20.0):
        if not isinstance(proof,RegistrationReadProof): raise ValueError
        code,_,value=self._send(READ_PATH+'status',proof._body(self._clock()),timeout_seconds)
        self._read_error(code,value); ch=proof._challenge
        if (set(value)!= {'schema_version','profile','operation_ref','kind','result','status'}
                or value['schema_version']!='ln_church.registration_read_result.v1'
                or value['profile']!=family(ch._task_type) or value['operation_ref']!=ch._ref): raise ValueError
        if value['kind']=='COMMITTED' and value['status'] is None:
            result=_success(value['result'],ch._task_type,ch._ref);state=None
        elif value['kind']=='STATUS' and value['result'] is None:
            result=None;state=_status(value['status'])
        else: raise ValueError
        return RegistrationReadResult(value['profile'],ch._ref,value['kind'],result,state)
