"""Closed, immutable Paid Service Trial DTOs; private bearer never serializes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, field_validator, model_validator
from . import paid_service_trial_contract as c


class _Frozen(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', frozen=True, hide_input_in_errors=True)

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
            return
        except Exception:
            data.clear()
        raise ValueError('Invalid Paid Service Trial wire value.')

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        try:
            if isinstance(obj, cls):
                obj = obj.model_dump(mode='python',exclude_unset=True)
            if isinstance(obj, Mapping):
                return cls(**dict(obj))
        except Exception:
            pass
        raise ValueError('Invalid Paid Service Trial wire value.')

    @classmethod
    def model_validate_json(cls, data: Any, **kwargs: Any) -> Any:
        try:
            return cls.model_validate(c.decode_json_object(data.encode() if isinstance(data,str) else data, 4*1024*1024))
        except Exception:
            pass
        raise ValueError('Invalid Paid Service Trial wire value.')

    @field_validator('*', mode='before')
    @classmethod
    def _nested(cls, value: Any) -> Any:
        return value.model_dump(mode='python',exclude_unset=True) if isinstance(value, _Frozen) else value


class PaymentExtra(_Frozen):
    name: Literal['USD Coin']
    version: Literal['2']
    assetTransferMethod: Literal['eip3009'] = 'eip3009'


class PaymentRequirements(_Frozen):
    scheme: Literal['exact']
    network: Literal['eip155:8453']
    asset: Literal['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913']
    amount: str
    payTo: str
    maxTimeoutSeconds: int = Field(gt=0, le=9007199254740991)
    extra: PaymentExtra

    _amount = field_validator('amount')(c.amount)
    _payto = field_validator('payTo')(c.address)

    def wire(self) -> dict:
        out = self.model_dump(mode='json')
        if 'assetTransferMethod' not in self.extra.model_fields_set:
            out['extra'].pop('assetTransferMethod')
        return out


class PurchaseTerms(_Frozen):
    x402_version: Literal[2]
    authorization_method: Literal['EIP-3009']
    requirements: PaymentRequirements

    @field_validator('x402_version', mode='before')
    @classmethod
    def _int_version(cls, value: Any) -> int:
        if type(value) is not int:
            raise ValueError
        return value

    def wire(self) -> dict:
        return dict(x402_version=2, authorization_method='EIP-3009', requirements=self.requirements.wire())


class Reward(_Frozen):
    network: Literal['eip155:8453']
    asset: Literal['USDC']
    asset_address: Literal['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913']
    amount_atomic: Literal['20000']


class _DefinitionBinding(_Frozen):
    task_id: str
    task_type: Literal['paid_service_trial.v1']
    task_definition_version: Literal['1.0.0']
    task_definition_digest: str
    terms_digest: str
    _task = field_validator('task_id')(c.validate_task_id)
    _digests = field_validator('task_definition_digest','terms_digest')(c.validate_sha256)


class _Offer(_DefinitionBinding):
    endpoint: str = Field(repr=False)
    purchase_terms: PurchaseTerms
    repeat_policy: Literal['ALLOW_REPEAT','ONCE_PER_OFFER_REWARD_ADDRESS']
    reward: Reward
    _endpoint = field_validator('endpoint')(c.endpoint)

    def model_dump(self, **kwargs: Any) -> dict:
        data = super().model_dump(**kwargs)
        if 'purchase_terms' in data:
            data['purchase_terms'] = self.purchase_terms.wire()
        return data


class PaidServiceTrialTask(_Offer):
    schema_version: Literal['ln_church.agent_task.paid_service_trial.v1']
    plan_id: Literal['C40','C400','C4000']
    registration_amount_atomic: Literal['1000000','10000000','100000000']
    status: Literal['OPEN','LISTING_ENDED','CLOSED']
    published_at: str
    listing_ends_at: str
    capacity_total: int = Field(ge=0)
    capacity_reserved: int = Field(ge=0)
    capacity_consumed: int = Field(ge=0)
    capacity_available: int = Field(ge=0)
    definition_url: str
    summary_url: str
    results_url: str

    def public_terms(self) -> dict:
        data = self.model_dump(mode='json')
        return {key:data[key] for key in ('endpoint','purchase_terms','plan_id','registration_amount_atomic','capacity_total','repeat_policy','reward')}

    @model_validator(mode='after')
    def _binding(self) -> Any:
        n = {'C40':40,'C400':400,'C4000':4000}[self.plan_id]
        path = '/api/agent/task-offers/' + self.task_id
        if (self.capacity_total != n or int(self.registration_amount_atomic) != n*25000
                or self.capacity_available != n-self.capacity_reserved-self.capacity_consumed
                or c.instant_ms(self.listing_ends_at)-c.instant_ms(self.published_at) != 172800000
                or self.definition_url != c.DEFINITION_URL
                or self.summary_url != c.PUBLIC_API_ORIGIN+path+'/summary'
                or self.results_url != c.PUBLIC_API_ORIGIN+path+'/execution-summaries'
                or c.digest(self.public_terms()) != self.terms_digest):
            raise ValueError
        return self


class PaidServiceTrialTaskPage(_Frozen):
    schema_version: Literal['ln_church.agent_task_page.paid_service_trial.v1']
    tasks: Tuple[PaidServiceTrialTask, ...]
    next_cursor: Optional[str]

    @field_validator('tasks',mode='before')
    @classmethod
    def _tasks(cls, value: Any) -> Any:
        if type(value) not in (list,tuple) or len(value)>50:
            raise ValueError
        return tuple(value)

    @field_validator('next_cursor')
    @classmethod
    def _cursor(cls, value: Any) -> Any:
        return c.cursor(value) if value is not None else None


class PaidServiceTrialClaim(_Offer):
    schema_version: Literal['ln_church.agent_task_claim_response.paid_service_trial.v1']
    execution_id: str
    reward_address: str = Field(repr=False)
    reward_address_control_verified: Literal[False]
    claim_accepted_at: str
    report_deadline: str
    purchase_block_timestamp_exclusive_min: str
    _claim_token: SecretStr = PrivateAttr()
    _address = field_validator('reward_address')(c.address)

    def __init__(self, **data: Any) -> None:
        raw = data.pop('claim_token',None)
        try:
            token = c.validate_claim_token(raw)
            super().__init__(**data)
            self._claim_token = SecretStr(token)
            return
        except Exception:
            data.clear()
            raw = None
        raise ValueError('Invalid Paid Service Trial Claim.')

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        try:
            if isinstance(obj,cls):
                obj = obj._private_payload()
            return cls(**dict(obj))
        except Exception:
            pass
        raise ValueError('Invalid Paid Service Trial Claim.')

    @field_validator('reward_address_control_verified',mode='before')
    @classmethod
    def _false(cls,value: Any) -> bool:
        if value is not False:
            raise ValueError
        return value

    @model_validator(mode='after')
    def _binding(self) -> Any:
        c.validate_opaque_id(self.execution_id,'execution_id')
        accepted = c.instant_ms(self.claim_accepted_at)
        if (c.instant_ms(self.report_deadline)-accepted != 600000
                or int(c.uint(self.purchase_block_timestamp_exclusive_min)) != accepted//1000):
            raise ValueError
        return self

    def _claim_token_value(self) -> str:
        return self._claim_token.get_secret_value()

    def _private_payload(self) -> dict:
        return dict(self.model_dump(mode='json'), claim_token=self._claim_token_value())

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError('Private Claim credentials cannot be pickled.')

    def __getstate__(self) -> Any:
        raise TypeError('Private Claim credentials cannot be pickled.')


class PaidServiceTrialAbandonment(_Frozen):
    schema_version: Literal['ln_church.agent_task_abandon_response.paid_service_trial.v1']
    task_id: str
    execution_id: str
    state: Literal['abandoned']
    abandoned_at: str
    _task = field_validator('task_id')(c.validate_task_id)

    @model_validator(mode='after')
    def _fields(self) -> Any:
        c.validate_opaque_id(self.execution_id,'execution_id'); c.instant_ms(self.abandoned_at)
        return self


class PurchaseIdentity(_Frozen):
    network: Literal['eip155:8453']
    asset: Literal['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913']
    payer: str
    authorization_nonce: str
    payTo: str
    amount: str
    validAfter: str
    validBefore: str
    _addresses = field_validator('payer','payTo')(c.address)
    _nonce = field_validator('authorization_nonce')(c.hash32)
    _amount = field_validator('amount')(c.amount)
    _validity = field_validator('validAfter','validBefore')(c.uint)

    @model_validator(mode='after')
    def _times(self) -> Any:
        if int(self.validAfter) >= int(self.validBefore):
            raise ValueError
        return self


class PaidServiceTrialReport(_DefinitionBinding):
    schema_version: Literal['ln_church.task_completion.paid_service_trial.v1']
    execution_id: str
    submission_id: str
    purchase: PurchaseIdentity
    transaction_hash: Optional[str] = None
    _submission = field_validator('submission_id')(c.validate_submission_id)

    @field_validator('transaction_hash',mode='before')
    @classmethod
    def _tx(cls,value: Any) -> str:
        return c.hash32(value)  # explicit null is invalid; omission is allowed

    @model_validator(mode='after')
    def _execution(self) -> Any:
        c.validate_opaque_id(self.execution_id,'execution_id')
        return self

    def wire(self) -> dict:
        return self.model_dump(mode='json',exclude_none=True)

    def require_claim(self, claim: PaidServiceTrialClaim) -> None:
        for key in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest','execution_id'):
            if getattr(self,key) != getattr(claim,key):
                raise ValueError('Invalid report binding.')
        req = claim.purchase_terms.requirements
        if self.purchase.payer != claim.reward_address or self.purchase.payTo != req.payTo or self.purchase.amount != req.amount:
            raise ValueError('Invalid report purchase binding.')


@dataclass(frozen=True, repr=False)
class FrozenPaidServiceTrialReport:
    _bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        data = c.v2_decode_json(self._bytes)
        version = c.version_of(data)
        report = model_for('report', version).model_validate(data)
        object.__setattr__(self,'_bytes',c.version_bytes(report.wire(), version))

    def __repr__(self) -> str:
        return 'FrozenPaidServiceTrialReport(<nonsecret identifying report>)'

    @classmethod
    def from_dict(cls, data: dict) -> Any:
        return cls(c.version_bytes(data, c.version_of(data)))

    @property
    def model(self) -> PaidServiceTrialReport:
        data = c.v2_decode_json(self._bytes)
        return model_for('report', c.version_of(data)).model_validate(data)

    @property
    def report_sha256(self) -> str:
        data = self.model.wire(); data.pop('transaction_hash',None)
        return c.version_digest(data, c.version_of(data))

    @property
    def submission_id(self) -> str:
        return self.model.submission_id

    def to_bytes(self) -> bytes:
        return self._bytes

    def supplement(self, transaction_hash: str) -> Any:
        return type(self).from_dict(dict(self.model.wire(), transaction_hash=c.hash32(transaction_hash)))


class _ReceiptIdentity(_Frozen):
    task_id: str
    execution_id: str
    submission_id: str
    terms_digest: str
    report_sha256: str
    received_at: str
    verification_deadline: str
    _task = field_validator('task_id')(c.validate_task_id)
    _sub = field_validator('submission_id')(c.validate_submission_id)
    _digests = field_validator('terms_digest','report_sha256')(c.validate_sha256)

    @model_validator(mode='after')
    def _binding(self) -> Any:
        c.validate_opaque_id(self.execution_id,'execution_id')
        if c.instant_ms(self.verification_deadline)-c.instant_ms(self.received_at)!=3600000:
            raise ValueError
        return self

    def require_report(self,claim: PaidServiceTrialClaim, report: FrozenPaidServiceTrialReport) -> None:
        model = report.model; model.require_claim(claim)
        if not self.schema_version.endswith('.' + c.version_of(claim)):
            raise ValueError('Invalid completion version.')
        if any(getattr(self,k)!=getattr(model,k) for k in ('task_id','execution_id','submission_id','terms_digest')) or self.report_sha256!=report.report_sha256 or c.instant_ms(self.received_at)>=c.instant_ms(claim.report_deadline):
            raise ValueError('Invalid completion binding.')


class PaidServiceTrialCompletionReceipt(_ReceiptIdentity):
    schema_version: Literal['ln_church.task_completion_receipt.paid_service_trial.v1']
    receipt_state: Literal['accepted']
    status_url: str

    @model_validator(mode='after')
    def _url(self) -> Any:
        if self.status_url != c.PUBLIC_API_ORIGIN+c.task_status_path(self.task_id,self.submission_id):
            raise ValueError
        return self


class _Transaction(_Frozen):
    transaction_hash: Optional[str]
    transaction_url: Optional[str]

    @model_validator(mode='after')
    def _tx(self) -> Any:
        if self.transaction_hash is None:
            if self.transaction_url is not None:
                raise ValueError
        elif self.transaction_url != 'https://basescan.org/tx/'+c.hash32(self.transaction_hash):
            raise ValueError
        return self


class PurchaseVerification(_Transaction):
    state: Literal['PENDING','VERIFIED','MISMATCH','PAYMENT_ALREADY_USED','INCONCLUSIVE']
    reason: Optional[str]
    verified_at: Optional[str]

    @model_validator(mode='after')
    def _value(self) -> Any:
        if self.reason is not None and self.reason not in c.SAFE_REASONS:
            raise ValueError
        if self.verified_at is not None:
            c.instant_ms(self.verified_at)
        return self


class Evaluation(_Frozen):
    state: Literal['PENDING','APPROVED','MISMATCH','PAYMENT_ALREADY_USED','INCONCLUSIVE']
    approved_amount_atomic: Optional[Literal['0','20000']]
    evaluated_at: Optional[str]

    @model_validator(mode='after')
    def _state(self) -> Any:
        amount = None if self.state=='PENDING' else ('20000' if self.state=='APPROVED' else '0')
        if self.approved_amount_atomic != amount or (self.state=='PENDING' and self.evaluated_at is not None):
            raise ValueError
        if self.evaluated_at is not None:
            c.instant_ms(self.evaluated_at)
        return self


class Payout(_Transaction):
    state: Literal['not_applicable','pending','processing','retryable','ambiguous','failed','paid_confirmed']
    confirmed_paid_amount_atomic: Optional[Literal['0','20000']]
    paid_confirmed_at: Optional[str]

    @model_validator(mode='after')
    def _state(self) -> Any:
        if (self.state=='paid_confirmed') != (self.confirmed_paid_amount_atomic=='20000'):
            raise ValueError
        if self.paid_confirmed_at is not None:
            c.instant_ms(self.paid_confirmed_at)
            if self.state!='paid_confirmed':
                raise ValueError
        return self


class PaidServiceTrialSubmissionStatus(_ReceiptIdentity):
    schema_version: Literal['ln_church.task_submission_status.paid_service_trial.v1']
    purchase_verification: PurchaseVerification
    evaluation: Evaluation
    payout: Payout
    updated_at: str

    @model_validator(mode='after')
    def _state(self) -> Any:
        c.instant_ms(self.updated_at)
        if self.evaluation.state!='APPROVED' and self.payout.state!='not_applicable':
            raise ValueError
        if self.evaluation.state=='APPROVED' and self.purchase_verification.state!='VERIFIED':
            raise ValueError
        return self


class PaidServiceRequest(_Frozen):
    schema_version: Literal['ln_church.paid_service_request.v2']
    method: Literal['GET', 'POST']
    url: str
    content_type: Optional[Literal['application/json']]
    body: Optional[str]
    body_sha256: Optional[str]

    @model_validator(mode='after')
    def _request(self) -> Any:
        c.validate_request(self.model_dump(mode='json'))
        return self


class _OfferV2(_DefinitionBinding):
    task_type: Literal['paid_service_trial.v2']
    task_definition_version: Literal['2.0.0']
    request: PaidServiceRequest
    request_digest: str
    purchase_terms_digest: str
    purchase_terms: PurchaseTerms
    repeat_policy: Literal['ALLOW_REPEAT', 'ONCE_PER_OFFER_REWARD_ADDRESS']
    reward: Reward
    _request_digests = field_validator('request_digest', 'purchase_terms_digest')(c.validate_sha256)

    def model_dump(self, **kwargs: Any) -> dict:
        data = super().model_dump(**kwargs)
        if 'purchase_terms' in data:
            data['purchase_terms'] = self.purchase_terms.wire()
        return data

    @model_validator(mode='after')
    def _request_binding(self) -> Any:
        request = self.request.model_dump(mode='json')
        if (c.v2_digest(request) != self.request_digest
                or c.purchase_terms_digest(request, self.purchase_terms) != self.purchase_terms_digest):
            raise ValueError
        c.v2_canonical_bytes(self.model_dump(mode='json'))
        return self

class PaidServiceTrialTaskV2(_OfferV2):
    schema_version: Literal['ln_church.agent_task.paid_service_trial.v2']
    plan_id: Literal['C40','C400','C4000']
    registration_amount_atomic: Literal['1000000','10000000','100000000']
    status: Literal['OPEN','LISTING_ENDED','CLOSED']
    published_at: str
    listing_ends_at: str
    capacity_total: int = Field(ge=0)
    capacity_reserved: int = Field(ge=0)
    capacity_consumed: int = Field(ge=0)
    capacity_available: int = Field(ge=0)
    definition_url: str
    summary_url: str
    results_url: str

    def public_terms(self) -> dict:
        data = self.model_dump(mode='json')
        return {key:data[key] for key in ('request','request_digest','purchase_terms_digest','purchase_terms','plan_id','registration_amount_atomic','capacity_total','repeat_policy','reward')}

    @model_validator(mode='after')
    def _binding(self) -> Any:
        n = {'C40':40,'C400':400,'C4000':4000}[self.plan_id]
        path = '/api/agent/task-offers/' + self.task_id
        if (self.capacity_total != n or int(self.registration_amount_atomic) != n*25000
                or self.capacity_available != n-self.capacity_reserved-self.capacity_consumed
                or c.instant_ms(self.listing_ends_at)-c.instant_ms(self.published_at) != 172800000
                or self.definition_url != c.V2_DEFINITION_URL
                or self.summary_url != c.PUBLIC_API_ORIGIN+path+'/summary'
                or self.results_url != c.PUBLIC_API_ORIGIN+path+'/execution-summaries'
                or c.v2_digest(self.public_terms()) != self.terms_digest):
            raise ValueError
        return self


class PaidServiceTrialTaskPageV2(_Frozen):
    schema_version: Literal['ln_church.agent_task_page.paid_service_trial.v2']
    tasks: Tuple[PaidServiceTrialTaskV2, ...]
    next_cursor: Optional[str]

    @field_validator('tasks',mode='before')
    @classmethod
    def _tasks(cls, value: Any) -> Any:
        if type(value) not in (list,tuple) or len(value)>50:
            raise ValueError
        return tuple(value)

    @field_validator('next_cursor')
    @classmethod
    def _cursor(cls, value: Any) -> Any:
        return c.cursor(value) if value is not None else None


class PaidServiceTrialClaimV2(_OfferV2):
    schema_version: Literal['ln_church.agent_task_claim_response.paid_service_trial.v2']
    execution_id: str
    reward_address: str = Field(repr=False)
    reward_address_control_verified: Literal[False]
    claim_accepted_at: str
    report_deadline: str
    purchase_block_timestamp_exclusive_min: str
    _claim_token: SecretStr = PrivateAttr()
    _address = field_validator('reward_address')(c.address)

    def __init__(self, **data: Any) -> None:
        raw = data.pop('claim_token',None)
        try:
            token = c.validate_claim_token(raw)
            super().__init__(**data)
            self._claim_token = SecretStr(token)
            return
        except Exception:
            data.clear()
            raw = None
        raise ValueError('Invalid Paid Service Trial Claim.')

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        try:
            if isinstance(obj,cls):
                obj = obj._private_payload()
            return cls(**dict(obj))
        except Exception:
            pass
        raise ValueError('Invalid Paid Service Trial Claim.')

    @field_validator('reward_address_control_verified',mode='before')
    @classmethod
    def _false(cls,value: Any) -> bool:
        if value is not False:
            raise ValueError
        return value

    @model_validator(mode='after')
    def _binding(self) -> Any:
        c.validate_opaque_id(self.execution_id,'execution_id')
        accepted = c.instant_ms(self.claim_accepted_at)
        if (c.instant_ms(self.report_deadline)-accepted != 600000
                or int(c.uint(self.purchase_block_timestamp_exclusive_min)) != accepted//1000):
            raise ValueError
        return self

    def _claim_token_value(self) -> str:
        return self._claim_token.get_secret_value()

    def _private_payload(self) -> dict:
        return dict(self.model_dump(mode='json'), claim_token=self._claim_token_value())

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError('Private Claim credentials cannot be pickled.')

    def __getstate__(self) -> Any:
        raise TypeError('Private Claim credentials cannot be pickled.')



class PaidServiceTrialAbandonmentV2(PaidServiceTrialAbandonment):
    schema_version: Literal['ln_church.agent_task_abandon_response.paid_service_trial.v2']


class PaidServiceTrialReportV2(PaidServiceTrialReport):
    schema_version: Literal['ln_church.task_completion.paid_service_trial.v2']
    task_type: Literal['paid_service_trial.v2']
    task_definition_version: Literal['2.0.0']
    request_digest: str
    purchase_terms_digest: str
    _request_digests = field_validator('request_digest', 'purchase_terms_digest')(c.validate_sha256)

    def require_claim(self, claim: Any) -> None:
        super().require_claim(claim)
        if (self.request_digest != claim.request_digest
                or self.purchase_terms_digest != claim.purchase_terms_digest):
            raise ValueError('Invalid report request binding.')


class PaidServiceTrialCompletionReceiptV2(PaidServiceTrialCompletionReceipt):
    schema_version: Literal['ln_church.task_completion_receipt.paid_service_trial.v2']


class PaidServiceTrialSubmissionStatusV2(PaidServiceTrialSubmissionStatus):
    schema_version: Literal['ln_church.task_submission_status.paid_service_trial.v2']


def model_for(surface: str, version: str) -> Any:
    c.validate_version(version)
    return _MODELS[version][surface]


def parse_claim(value: Any) -> Any:
    return model_for('claim', c.version_of(value)).model_validate(value)


_MODELS = {
    'v1': dict(task=PaidServiceTrialTask, page=PaidServiceTrialTaskPage,
        claim=PaidServiceTrialClaim, report=PaidServiceTrialReport,
        receipt=PaidServiceTrialCompletionReceipt, status=PaidServiceTrialSubmissionStatus,
        abandon=PaidServiceTrialAbandonment),
    'v2': dict(task=PaidServiceTrialTaskV2, page=PaidServiceTrialTaskPageV2,
        claim=PaidServiceTrialClaimV2, report=PaidServiceTrialReportV2,
        receipt=PaidServiceTrialCompletionReceiptV2, status=PaidServiceTrialSubmissionStatusV2,
        abandon=PaidServiceTrialAbandonmentV2),
}
