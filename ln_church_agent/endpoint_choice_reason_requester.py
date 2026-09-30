"""Private registration input and explicit, memory-only requester result proofs."""
from __future__ import annotations
import copy
import hashlib
import re
import time
from typing import Optional, Tuple, Literal
from pydantic import Field, model_validator, field_validator

from . import endpoint_choice_reason_contract as c
from .endpoint_choice_reason_models import _Frozen, EndpointChoiceResultRow
from .endpoint_choice_reason_transport import EndpointChoiceTransport, EndpointChoiceError, public_boundary
from .paid_service_trial_contract import decode_base64_object


def prepare_registration(value):
    """Validate B1 before any fee challenge; preserve text and correct-ID order."""
    failed = False
    try:
        if isinstance(value, bytes): value = c.decode_json_object(value, 65536)
        if type(value) is not dict or set(value) != {'task_type', 'plan_id', 'question', 'candidates', 'correct_candidate_ids', 'reveal_correct_set_after_answer'}:
            raise ValueError
        if value['task_type'] != c.TASK_TYPE or value['plan_id'] not in c.PLANS or type(value['reveal_correct_set_after_answer']) is not bool:
            raise ValueError
        c.text_value(value['question'], 4096)
        if type(value['candidates']) is not list or not 1 <= len(value['candidates']) <= 10:
            raise ValueError
        result = copy.deepcopy(value)
        for candidate in result['candidates']:
            if type(candidate) is not dict or set(candidate) not in ({'candidate_id', 'url'}, {'candidate_id', 'url', 'evaluator_description'}):
                raise ValueError
            c.candidate_id(candidate['candidate_id'])
            candidate['url'] = c.prepare_url(candidate['url'])
            if 'evaluator_description' in candidate:
                c.text_value(candidate['evaluator_description'], 2048)
        ids = [x['candidate_id'] for x in result['candidates']]
        urls = [x['url'] for x in result['candidates']]
        correct = result['correct_candidate_ids']
        if (len(set(ids)) != len(ids) or len(set(urls)) != len(urls) or type(correct) is not list
                or not correct or any(type(x) is not str for x in correct)
                or len(set(correct)) != len(correct) or not set(correct) <= set(ids)):
            raise ValueError
        projection = dict(question=result['question'], candidates=[dict(candidateId=x['candidate_id'], endpoint=x['url'],
            **({'description': x['evaluator_description']} if 'evaluator_description' in x else {})) for x in result['candidates']])
        c.canonical_bytes(projection, 16384)
        c.canonical_bytes(result, 65536)
        return EndpointChoiceRegistrationInput(result)
    except Exception:
        failed = True
    if failed:
        raise ValueError('Invalid endpoint choice registration.')


class EndpointChoiceRegistrationInput:
    __slots__ = ('_wire',)
    def __init__(self, validated):
        self._wire = c.canonical_bytes(validated, 65536)
    def __repr__(self): return 'EndpointChoiceRegistrationInput(<private>)'
    def _private_payload(self): return c.decode_json_object(self._wire, 65536)
    def __reduce_ex__(self, protocol): raise TypeError('Private registration input cannot be pickled.')


def registration_operation_ref(original_payment_header):
    """Derive B3's non-secret reference from the original signed x402 envelope.

    This is a locator, not proof of settlement, publication or payer control.
    """
    failed = False
    try:
        p = decode_base64_object(original_payment_header)
        accepted, auth = p['accepted'], p['payload']['authorization']
        if p['x402Version'] != 2 or accepted['network'] != 'eip155:8453' or c.address(accepted['asset']) != c.ASSET:
            raise ValueError
        nonce = auth['nonce']
        if type(nonce) is not str or re.fullmatch(r'0x[0-9a-fA-F]{64}', nonce) is None:
            raise ValueError
        g = c.digest(['ln-church/x402-eip3009/v1', 'eip155:8453', c.ASSET, c.address(auth['from']), nonce.lower()])
        s = hashlib.sha256(('endpoint-choice-reason-registration\0' + g).encode()).hexdigest()
        return s[:8] + '-' + s[8:12] + '-4' + s[13:16] + '-8' + s[17:20] + '-' + s[20:32]
    except Exception:
        failed = True
    if failed: raise ValueError('Invalid original registration payment binding.')


_DOMAIN = dict(name='LNChurch Offer Results', version='1', chainId=8453)
_FIELDS = [('audience','string'), ('action','string'), ('taskId','string'), ('payer','address'),
           ('nonce','bytes32'), ('issuedAt','uint256'), ('expiresAt','uint256')]
_TYPES = {'EIP712Domain': [dict(name=k, type=v) for k,v in [('name','string'), ('version','string'), ('chainId','uint256')]],
          'OfferResultsRead': [dict(name=k, type=v) for k,v in _FIELDS]}


def _challenge(value, task_id, payer, now):
    if type(value) is not dict or set(value) != {'schema_version', 'challenge_token', 'typed_data'} or value['schema_version'] != 'ln_church.offer_results_challenge.v1':
        raise ValueError('Invalid results challenge.')
    token, typed = value['challenge_token'], value['typed_data']
    if type(token) is not str or not token or len(token.encode()) > 8192:
        raise ValueError('Invalid results token.')
    if type(typed) is not dict or set(typed) != {'domain', 'types', 'primaryType', 'message'}:
        raise ValueError('Invalid results typed data.')
    if typed['domain'] != _DOMAIN or type(typed['domain'].get('chainId')) is not int or typed['types'] != _TYPES or typed['primaryType'] != 'OfferResultsRead':
        raise ValueError('Invalid results purpose.')
    m = typed['message']
    if type(m) is not dict or set(m) != {k for k,_ in _FIELDS}:
        raise ValueError('Invalid results scope.')
    if (m['audience'] != c.PUBLIC_API_ORIGIN + '/api/agent/task-offer-results/read' or m['action'] != 'read_offer_results'
            or m['taskId'] != c.validate_task_id(task_id) or m['payer'] != c.address(payer)
            or type(m['nonce']) is not str or re.fullmatch(r'0x[0-9a-f]{64}', m['nonce']) is None):
        raise ValueError('Invalid results scope.')
    c.atomic(m['issuedAt']); c.atomic(m['expiresAt'])
    if int(m['expiresAt']) != int(m['issuedAt']) + 300 or not int(m['issuedAt']) <= now < int(m['expiresAt']):
        raise ValueError('Results challenge is not live.')
    return copy.deepcopy(value)


class OfferResultsChallenge:
    __slots__ = ('_wire', '_task_id', '_payer')
    def __init__(self, payload, *, task_id, payer, now=None):
        value = _challenge(payload, task_id, payer, time.time() if now is None else now)
        self._wire = c.canonical_bytes(value)
        self._task_id, self._payer = task_id, c.address(payer)
    def __repr__(self): return 'OfferResultsChallenge(<private>)'
    def __reduce_ex__(self, protocol): raise TypeError('Read proofs stay in memory.')
    @public_boundary
    def sign(self, signer, *, now=None):
        """Explicit callback; never invoked by page reads or automatic renewal.

        The callback receives a private typed-data copy and returns an EOA or
        deployed ERC-1271-compatible hex signature; server verifies payer control.
        """
        value = _challenge(c.decode_json_object(self._wire, 16384), self._task_id, self._payer,
                           time.time() if now is None else now)
        failed = False
        try:
            signature = signer(copy.deepcopy(value['typed_data']))
            if type(signature) is not str or re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', signature) is None:
                raise ValueError
        except Exception:
            failed = True
        if failed: raise ValueError('Results proof signing failed.')
        return OfferResultsProof(self, signature)


class OfferResultsProof:
    __slots__ = ('_wire', '_task_id', '_payer')
    def __init__(self, challenge, signature):
        self._wire = c.canonical_bytes(dict(c.decode_json_object(challenge._wire, 16384), signature=signature), 32768)
        self._task_id, self._payer = challenge._task_id, challenge._payer
    def __repr__(self): return 'OfferResultsProof(<private>)'
    def __reduce_ex__(self, protocol): raise TypeError('Read proofs stay in memory.')
    def _read_body(self, limit, cursor, now):
        c.positive_bound(limit, 'limit', integer=True, maximum=50); c.cursor(cursor)
        d = c.decode_json_object(self._wire, 32768)
        signature = d.pop('signature')
        _challenge(d, self._task_id, self._payer, now)
        return c.canonical_bytes(dict(schema_version='ln_church.offer_results_read_request.v1',
            challenge_token=d['challenge_token'], typed_data=d['typed_data'], signature=signature, limit=limit, cursor=cursor), 32768)


class _OwnerCandidate(_Frozen):
    candidate_id: str
    url: str
    description_state: Literal['NOT_PROVIDED', 'RETAINED', 'DELETED']
    evaluator_description: Optional[str] = Field(repr=False, exclude=True)
    @model_validator(mode='after')
    def _check(self):
        c.candidate_id(self.candidate_id); c.prepare_url(self.url)
        if self.description_state == 'RETAINED': c.text_value(self.evaluator_description, 2048)
        elif self.evaluator_description is not None: raise ValueError('Description outside retention.')
        return self


class _OwnerRegistration(_Frozen):
    task_type: Literal['endpoint_choice_reason.v1']
    plan_id: Literal['C5', 'C55', 'C555']
    question: str
    candidates: Tuple[_OwnerCandidate, ...] = Field(repr=False, exclude=True)
    correct_candidate_ids: Tuple[str, ...] = Field(repr=False, exclude=True)
    reveal_correct_set_after_answer: bool
    description_retention_state: Literal['NOT_PROVIDED', 'RETAINED', 'DELETED']
    description_delete_at: Optional[str]
    @field_validator('candidates', 'correct_candidate_ids', mode='before')
    @classmethod
    def _tuple(cls, value):
        if type(value) not in (list, tuple): raise ValueError('Invalid owner array.')
        return tuple(value)
    @model_validator(mode='after')
    def _check(self):
        c.text_value(self.question, 4096)
        ids = [x.candidate_id for x in self.candidates]
        if not 1 <= len(ids) <= 10 or len(set(ids)) != len(ids) or len({x.url for x in self.candidates}) != len(ids):
            raise ValueError('Invalid owner candidates.')
        if not self.correct_candidate_ids or len(set(self.correct_candidate_ids)) != len(self.correct_candidate_ids) or not set(self.correct_candidate_ids) <= set(ids):
            raise ValueError('Invalid owner correct set.')
        if self.description_delete_at is not None: c.validate_timestamp(self.description_delete_at)
        states = {x.description_state for x in self.candidates}
        expected = 'RETAINED' if 'RETAINED' in states else ('DELETED' if 'DELETED' in states else 'NOT_PROVIDED')
        if self.description_retention_state != expected: raise ValueError('Invalid retention state.')
        return self


class EndpointChoiceRequesterResults(_Frozen):
    schema_version: Literal['ln_church.offer_results_read_response.v1']
    task_id: str
    registration: _OwnerRegistration = Field(repr=False, exclude=True)
    items: Tuple[EndpointChoiceResultRow, ...] = Field(repr=False, exclude=True)
    next_cursor: Optional[str]
    intake_closed_at: Optional[str]
    projected_at: str
    @field_validator('items', mode='before')
    @classmethod
    def _items(cls, value):
        if type(value) not in (list, tuple) or len(value) > 50: raise ValueError('Invalid owner page.')
        return tuple(value)
    @model_validator(mode='after')
    def _check(self):
        c.validate_task_id(self.task_id); c.cursor(self.next_cursor); c.validate_timestamp(self.projected_at)
        if self.intake_closed_at is not None: c.validate_timestamp(self.intake_closed_at)
        return self


class EndpointChoiceRequesterClient:
    def __init__(self, *, transport=None, wall_time=time.time):
        if transport is not None and not isinstance(transport, EndpointChoiceTransport):
            raise ValueError('Invalid requester transport.')
        self._transport = transport or EndpointChoiceTransport()
        self._clock = wall_time
        self._owns = transport is None

    def close(self):
        if self._owns: self._transport.close()

    def registration_client(self):
        """A/B registration adapter sharing this pinned transport, without quota purchase."""
        from .offer_registration import OfferRegistrationClient
        return OfferRegistrationClient(transport=self._transport, wall_time=self._clock)

    @public_boundary
    def get_results_challenge(self, task_id, payer, *, timeout_seconds=20.0):
        payload = self._transport.results_challenge(task_id, payer, timeout_seconds=timeout_seconds)
        return OfferResultsChallenge(payload, task_id=task_id, payer=payer, now=self._clock())

    @public_boundary
    def read_results(self, proof, *, limit=20, cursor=None, timeout_seconds=20.0):
        if not isinstance(proof, OfferResultsProof): raise ValueError('Explicitly signed results proof required.')
        body = proof._read_body(limit, cursor, self._clock())
        payload = self._transport.results_read(body, timeout_seconds=timeout_seconds)
        result = EndpointChoiceRequesterResults.model_validate(payload)
        if result.task_id != proof._task_id:
            raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
        return result
