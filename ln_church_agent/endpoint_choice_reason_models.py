"""Strict, immutable new-family DTOs; private credentials never serialize publicly."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal, Optional, Tuple
import hashlib
import re

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, field_validator, model_validator
from . import endpoint_choice_reason_contract as c


class _Frozen(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', frozen=True, hide_input_in_errors=True)

    @model_validator(mode='after')
    def _version_tuple(self):
        schema = getattr(self, 'schema_version', '')
        if '.endpoint_choice_reason.' in schema:
            version = c.validate_version(schema.rsplit('.', 1)[-1])
            if hasattr(self, 'task_type') and c.version_of(self) != version:
                raise ValueError('Mixed endpoint choice schema.')
            if hasattr(self, 'task_definition_version') and self.task_definition_version != {'v1':'1.0.0', 'v2':'2.0.0'}[version]:
                raise ValueError('Mixed endpoint choice definition.')
            if hasattr(self, 'tasks') and any(c.version_of(t) != version for t in self.tasks):
                raise ValueError('Mixed endpoint choice page.')
        return self

    def __init__(self, **data):
        failed = False
        try:
            super().__init__(**data)
        except Exception:
            failed = True
        if failed:
            data.clear()
            raise ValueError('Invalid endpoint choice wire value.')

    @classmethod
    def model_validate(cls, value, **kwargs):
        if isinstance(value, cls):
            return cls(**value.model_dump(mode='python'))
        if not isinstance(value, dict):
            raise ValueError('Invalid endpoint choice wire value.')
        return cls(**dict(value))

    @classmethod
    def model_validate_json(cls, value, **kwargs):
        failed = False
        try:
            return cls.model_validate(c.decode_json_object(value.encode() if isinstance(value, str) else value, 4194304))
        except Exception:
            failed = True
        if failed:
            raise ValueError('Invalid endpoint choice JSON.')


class EndpointChoiceCandidate(_Frozen):
    candidate_id: str
    url: str

    @model_validator(mode='after')
    def _check(self):
        c.candidate_id(self.candidate_id)
        if c.prepare_url(self.url) != self.url:
            raise ValueError('Noncanonical URL.')
        return self


class EndpointChoiceReward(_Frozen):
    network: Literal['eip155:8453']
    asset: Literal['USDC']
    asset_address: str
    correct_amount_atomic: Literal['100000']
    incorrect_amount_atomic: Literal['10000']
    full_reward_threshold: Literal['0.7']
    rounding: Literal['FLOOR_ATOMIC']

    @field_validator('asset_address')
    @classmethod
    def _asset(cls, value):
        if c.address(value) != c.ASSET:
            raise ValueError('Invalid native USDC.')
        return value


class _Snapshot(_Frozen):
    task_id: str
    task_type: Literal['endpoint_choice_reason.v1', 'endpoint_choice_reason.v2']
    task_definition_version: Literal['1.0.0', '2.0.0']
    task_definition_digest: str
    terms_digest: str
    question: str
    candidates: Tuple[EndpointChoiceCandidate, ...]
    reveal_correct_set_after_answer: bool
    evaluation_profile_id: Literal['endpoint-choice-reason-jev-v1']
    reward: EndpointChoiceReward

    @field_validator('candidates', mode='before')
    @classmethod
    def _candidates(cls, value):
        if type(value) not in (list, tuple):
            raise ValueError('Invalid candidates.')
        return tuple(value)

    @model_validator(mode='after')
    def _snapshot(self):
        c.validate_task_id(self.task_id)
        c.require_definition(self.task_definition_digest, c.version_of(self))
        c.validate_sha256(self.terms_digest)
        c.text_value(self.question, 4096)
        if (not 1 <= len(self.candidates) <= 10
                or len({x.candidate_id for x in self.candidates}) != len(self.candidates)
                or len({x.url for x in self.candidates}) != len(self.candidates)):
            raise ValueError('Invalid candidates.')
        return self


class EndpointChoiceTask(_Snapshot):
    schema_version: Literal['ln_church.agent_task.endpoint_choice_reason.v1', 'ln_church.agent_task.endpoint_choice_reason.v2']
    plan_id: Literal['C5', 'C55', 'C555']
    registration_amount_atomic: str
    capacity_total: int = Field(ge=0, le=9007199254740991)
    capacity_reserved: int = Field(ge=0, le=9007199254740991)
    capacity_consumed: int = Field(ge=0, le=9007199254740991)
    capacity_available: int = Field(ge=0, le=9007199254740991)
    successful_claims_lifetime: Optional[int] = Field(ge=0, le=9007199254740991)
    rewards_paid_confirmed: Optional[int] = Field(ge=0, le=9007199254740991)
    pending_result_count: Optional[int] = Field(ge=0, le=9007199254740991)
    status: Literal['OPEN', 'LISTING_ENDED', 'CLOSED']
    published_at: str
    listing_ends_at: str
    answer_acceptance_closed_at: Optional[str]
    definition_url: str
    summary_url: str
    results_url: str

    @model_validator(mode='after')
    def _terms(self):
        if (self.registration_amount_atomic, self.capacity_total) != c.PLANS[self.plan_id]:
            raise ValueError('Invalid plan.')
        if self.capacity_total != self.capacity_reserved + self.capacity_consumed + self.capacity_available:
            raise ValueError('Invalid capacity.')
        payload = self.model_dump(mode='json')
        if c.digest({k: payload[k] for k in c.TERMS_FIELDS}) != self.terms_digest:
            raise ValueError('Invalid terms digest.')
        if c.parse_timestamp(self.listing_ends_at) - c.parse_timestamp(self.published_at) != timedelta(hours=168 if c.version_of(self) == "v2" else 48):
            raise ValueError('Invalid listing window.')
        if (self.status == 'CLOSED') != (self.answer_acceptance_closed_at is not None):
            raise ValueError('Invalid closure.')
        if self.answer_acceptance_closed_at is not None:
            c.validate_timestamp(self.answer_acceptance_closed_at)
        for value in (self.definition_url, self.summary_url, self.results_url):
            if not value.startswith(c.PUBLIC_API_ORIGIN + '/'):
                raise ValueError('Invalid public URL.')
        if c.version_of(self) == 'v2' and self.definition_url != c.PUBLIC_API_ORIGIN + '/agent-task-specs/endpoint_choice_reason.v2/2.0.0/SKILL.md':
            raise ValueError('Invalid Choice v2 definition URL.')
        if self.results_url != c.PUBLIC_API_ORIGIN + c.task_detail_path(self.task_id) + '/results':
            raise ValueError('Invalid results URL.')
        return self


class EndpointChoiceTaskPage(_Frozen):
    schema_version: Literal['ln_church.agent_task_page.endpoint_choice_reason.v1', 'ln_church.agent_task_page.endpoint_choice_reason.v2']
    tasks: Tuple[EndpointChoiceTask, ...]
    next_cursor: Optional[str]

    @field_validator('tasks', mode='before')
    @classmethod
    def _tasks(cls, value):
        if type(value) not in (list, tuple) or len(value) > 100:
            raise ValueError('Invalid tasks.')
        return tuple(value)

    @field_validator('next_cursor')
    @classmethod
    def _cursor(cls, value):
        return c.cursor(value)


class EndpointChoiceClaimCredential(_Snapshot):
    schema_version: Literal['ln_church.agent_task_claim_response.endpoint_choice_reason.v1', 'ln_church.agent_task_claim_response.endpoint_choice_reason.v2']
    execution_id: str
    reward_address: str = Field(repr=False, exclude=True)
    reward_address_control_verified: Literal[False]
    claim_accepted_at: str
    report_deadline: str
    _claim_token: SecretStr = PrivateAttr()

    def __init__(self, **data):
        token = data.pop('claim_token', None)
        failed = False
        try:
            token = c.validate_claim_token(token)
            super().__init__(**data)
            self._claim_token = SecretStr(token)
        except Exception:
            failed = True
        if failed:
            data.clear()
            token = None
            raise ValueError('Invalid endpoint choice credential.')

    @classmethod
    def model_validate(cls, value, **kwargs):
        if isinstance(value, cls):
            return cls(**value._private_payload())
        return super().model_validate(value)

    @model_validator(mode='after')
    def _claim(self):
        c.execution_id(self.execution_id)
        if c.address(self.reward_address) != self.reward_address or self.reward_address_control_verified is not False:
            raise ValueError('Invalid address binding.')
        if c.parse_timestamp(self.report_deadline) - c.parse_timestamp(self.claim_accepted_at) != timedelta(minutes=10):
            raise ValueError('Invalid Claim window.')
        return self

    def _claim_token_value(self):
        return self._claim_token.get_secret_value()

    def _private_payload(self):
        return dict(self.model_dump(mode='json'), reward_address=self.reward_address, claim_token=self._claim_token_value())

    def __reduce_ex__(self, protocol):
        raise TypeError('Private credentials cannot be pickled.')

    def __getstate__(self):
        raise TypeError('Private credentials cannot be pickled.')


class EndpointChoiceCompletionReport(_Frozen):
    schema_version: Literal['ln_church.task_completion.endpoint_choice_reason.v1', 'ln_church.task_completion.endpoint_choice_reason.v2']
    task_id: str
    task_type: Literal['endpoint_choice_reason.v1', 'endpoint_choice_reason.v2']
    task_definition_version: Literal['1.0.0', '2.0.0']
    task_definition_digest: str
    terms_digest: str
    execution_id: str
    submission_id: str
    selected_candidate_id: str
    answer_reason: str = Field(repr=False, exclude=True)

    @classmethod
    def model_validate(cls, value, **kwargs):
        if isinstance(value, cls):
            return cls(**value._private_payload())
        return super().model_validate(value, **kwargs)

    def _private_payload(self):
        return dict(self.model_dump(mode='json'), answer_reason=self.answer_reason)

    @model_validator(mode='after')
    def _check(self):
        c.validate_task_id(self.task_id)
        c.execution_id(self.execution_id)
        c.validate_submission_id(self.submission_id)
        c.require_definition(self.task_definition_digest, c.version_of(self))
        c.validate_sha256(self.terms_digest)
        c.candidate_id(self.selected_candidate_id)
        c.text_value(self.answer_reason, 8192)
        c.canonical_bytes(self._private_payload())
        return self


@dataclass(frozen=True, init=False)
class FrozenEndpointChoiceReport:
    canonical_bytes: bytes = field(repr=False)
    report_sha256: str = field(repr=False)

    def __init__(self, canonical_bytes):
        parsed = EndpointChoiceCompletionReport.model_validate(c.decode_json_object(canonical_bytes, c.MAX_REPORT_BYTES))
        if c.canonical_bytes(parsed._private_payload()) != canonical_bytes:
            raise ValueError('Noncanonical endpoint choice report.')
        object.__setattr__(self, 'canonical_bytes', bytes(canonical_bytes))
        object.__setattr__(self, 'report_sha256', hashlib.sha256(canonical_bytes).hexdigest())

    @classmethod
    def from_report(cls, report):
        payload = report._private_payload() if isinstance(report, EndpointChoiceCompletionReport) else report
        parsed = EndpointChoiceCompletionReport.model_validate(payload)
        return cls(c.canonical_bytes(parsed._private_payload()))

    @classmethod
    def from_bytes(cls, value):
        return cls(value)

    @property
    def report(self):
        return EndpointChoiceCompletionReport.model_validate(c.decode_json_object(self.canonical_bytes, c.MAX_REPORT_BYTES))

    def validate_claim(self, claim):
        report = self.report
        if (any(getattr(report, k) != getattr(claim, k) for k in ('task_id', 'task_type', 'task_definition_version',
                'task_definition_digest', 'terms_digest', 'execution_id'))
                or report.selected_candidate_id not in {x.candidate_id for x in claim.candidates}):
            raise ValueError('Report binding invalid.')
        return self


class EndpointChoiceEvaluation(_Frozen):
    state: Literal['PENDING', 'GRADED', 'COMPENSATED']
    is_correct: Optional[bool]
    q: Optional[str]
    applied_coefficient: Optional[str]
    reward_basis: Optional[Literal['SCORE_PROPORTIONAL', 'FULL_REWARD_LINE', 'OPERATOR_COMPENSATION']]
    base_amount_atomic: Optional[str]
    approved_amount_atomic: Optional[str]
    evaluated_at: Optional[str]

    @model_validator(mode='after')
    def _check(self):
        if self.state == 'PENDING':
            if any(v is not None for k, v in self.model_dump().items() if k != 'state'):
                raise ValueError('Premature evaluation facts.')
            return self
        if self.is_correct is None or self.approved_amount_atomic is None or self.evaluated_at is None:
            raise ValueError('Missing evaluation facts.')
        c.atomic(self.approved_amount_atomic)
        c.validate_timestamp(self.evaluated_at)
        c.decimal_string(self.applied_coefficient)
        if self.base_amount_atomic != ('100000' if self.is_correct else '10000'):
            raise ValueError('Invalid base reward.')
        if self.state == 'COMPENSATED':
            if (self.q is not None or self.applied_coefficient != '1' or self.reward_basis != 'OPERATOR_COMPENSATION'
                    or self.approved_amount_atomic != self.base_amount_atomic):
                raise ValueError('Invalid compensation.')
        else:
            c.decimal_string(self.q)
            full = Decimal(self.q) >= Decimal('0.7')
            if (self.applied_coefficient != ('1' if full else self.q)
                    or self.reward_basis != ('FULL_REWARD_LINE' if full else 'SCORE_PROPORTIONAL')):
                raise ValueError('Invalid coefficient.')
        # Amount is authoritative server data; SDK never grants or computes entitlement.
        return self


class EndpointChoicePayout(_Frozen):
    state: Literal['not_applicable', 'pending', 'processing', 'retryable', 'ambiguous', 'failed', 'paid_confirmed']
    transaction_hash: Optional[str]
    transaction_url: Optional[str]
    confirmed_paid_amount_atomic: Optional[str]
    paid_confirmed_at: Optional[str]

    @model_validator(mode='after')
    def _check(self):
        if self.confirmed_paid_amount_atomic is not None:
            c.atomic(self.confirmed_paid_amount_atomic)
        if self.transaction_hash is not None and re.fullmatch(r'0x[0-9a-fA-F]{64}', self.transaction_hash) is None:
            raise ValueError('Invalid transaction hash.')
        if self.paid_confirmed_at is not None:
            c.validate_timestamp(self.paid_confirmed_at)
        if self.transaction_url is not None and (self.transaction_hash is None or self.transaction_url != 'https://basescan.org/tx/' + self.transaction_hash):
            raise ValueError('Invalid transaction URL.')
        if self.state == 'paid_confirmed' and any(getattr(self, k) is None for k in ('transaction_hash', 'transaction_url', 'confirmed_paid_amount_atomic', 'paid_confirmed_at')):
            raise ValueError('Unconfirmed payout.')
        return self


def _evaluation_payout(evaluation, payout):
    if evaluation.state == 'PENDING' or evaluation.approved_amount_atomic == '0':
        amount = None if evaluation.state == 'PENDING' else '0'
        if payout.model_dump() != dict(state='not_applicable', transaction_hash=None, transaction_url=None, confirmed_paid_amount_atomic=amount, paid_confirmed_at=None):
            raise ValueError('Invalid no-payment state.')
    elif payout.state == 'not_applicable':
        raise ValueError('Positive reward needs payout state.')
    if payout.state == 'paid_confirmed' and payout.confirmed_paid_amount_atomic != evaluation.approved_amount_atomic:
        raise ValueError('Payout amount mismatch.')


class _ReceiptIdentity(_Frozen):
    task_id: str
    execution_id: str
    submission_id: str
    terms_digest: str
    report_sha256: str
    received_at: str
    evaluation_deadline: str

    @model_validator(mode='after')
    def _check(self):
        c.validate_task_id(self.task_id); c.execution_id(self.execution_id)
        c.validate_submission_id(self.submission_id)
        c.validate_sha256(self.terms_digest); c.validate_sha256(self.report_sha256)
        if c.parse_timestamp(self.evaluation_deadline) - c.parse_timestamp(self.received_at) != timedelta(minutes=30):
            raise ValueError('Invalid evaluation deadline.')
        return self

    def matches(self, frozen):
        report = frozen.report
        return (self.schema_version.rsplit('.', 1)[-1] == c.version_of(report) and all(getattr(self, k) == getattr(report, k) for k in ('task_id', 'execution_id', 'submission_id', 'terms_digest'))
                and self.report_sha256 == frozen.report_sha256)


class EndpointChoiceCompletionReceipt(_ReceiptIdentity):
    schema_version: Literal['ln_church.task_completion_receipt.endpoint_choice_reason.v1', 'ln_church.task_completion_receipt.endpoint_choice_reason.v2']
    receipt_state: Literal['accepted']
    status_url: str

    @model_validator(mode='after')
    def _link(self):
        path = c.task_status_path(self.task_id, self.submission_id)
        if self.status_url not in (path, c.PUBLIC_API_ORIGIN + path):
            raise ValueError('Invalid status URL.')
        return self


class EndpointChoiceSubmissionStatus(_ReceiptIdentity):
    schema_version: Literal['ln_church.task_submission_status.endpoint_choice_reason.v1', 'ln_church.task_submission_status.endpoint_choice_reason.v2']
    selected_candidate_id: str
    answer_reason: str = Field(repr=False, exclude=True)
    evaluation: EndpointChoiceEvaluation
    payout: EndpointChoicePayout
    correct_candidate_ids: Optional[Tuple[str, ...]] = Field(repr=False, exclude=True)
    updated_at: str

    @field_validator('correct_candidate_ids', mode='before')
    @classmethod
    def _ids(cls, value):
        if value is None: return None
        if type(value) not in (tuple, list) or not value or len(value) > 10 or len(set(value)) != len(value):
            raise ValueError('Invalid correct set.')
        return tuple(c.candidate_id(v) for v in value)

    @model_validator(mode='after')
    def _status(self):
        c.candidate_id(self.selected_candidate_id); c.text_value(self.answer_reason, 8192)
        c.validate_timestamp(self.updated_at)
        _evaluation_payout(self.evaluation, self.payout)
        if self.evaluation.state == 'PENDING' and self.correct_candidate_ids is not None:
            raise ValueError('Premature correct set.')
        return self


class EndpointChoiceResultRow(_Frozen):
    result_id: str
    selected_candidate_id: str
    answer_reason: str = Field(repr=False)
    received_at: str
    evaluation: EndpointChoiceEvaluation
    payout: EndpointChoicePayout
    updated_at: str

    @model_validator(mode='after')
    def _check(self):
        c.validate_opaque_id(self.result_id, 'result_id')
        if self.result_id.startswith(('exec_', 'sub_')):
            raise ValueError('Private ID in public row.')
        c.candidate_id(self.selected_candidate_id); c.text_value(self.answer_reason, 8192)
        c.validate_timestamp(self.received_at); c.validate_timestamp(self.updated_at)
        _evaluation_payout(self.evaluation, self.payout)
        return self


class EndpointChoiceCounts(_Frozen):
    capacity_total: int = Field(ge=0, le=9007199254740991)
    capacity_reserved: int = Field(ge=0, le=9007199254740991)
    capacity_consumed: int = Field(ge=0, le=9007199254740991)
    evaluations_pending: int = Field(ge=0, le=9007199254740991)
    evaluations_final: int = Field(ge=0, le=9007199254740991)
    successful_claims_lifetime: Optional[int] = Field(ge=0, le=9007199254740991)
    rewards_paid_confirmed: Optional[int] = Field(ge=0, le=9007199254740991)
    pending_result_count: Optional[int] = Field(ge=0, le=9007199254740991)


class EndpointChoicePublicResults(_Frozen):
    schema_version: Literal['ln_church.task_results.endpoint_choice_reason.v1', 'ln_church.task_results.endpoint_choice_reason.v2']
    task_id: str
    task_type: Literal['endpoint_choice_reason.v1', 'endpoint_choice_reason.v2']
    answer_acceptance_closed_at: Optional[str]
    visibility: Literal['WITHHELD_UNTIL_ANSWER_CLOSURE', 'PUBLIC']
    counts: EndpointChoiceCounts
    rows: Tuple[EndpointChoiceResultRow, ...]
    next_cursor: Optional[str]
    updated_at: str

    @field_validator('rows', mode='before')
    @classmethod
    def _rows(cls, value):
        if type(value) not in (list, tuple) or len(value) > 50:
            raise ValueError('Invalid results page.')
        return tuple(value)

    @model_validator(mode='after')
    def _public(self):
        c.validate_task_id(self.task_id); c.cursor(self.next_cursor); c.validate_timestamp(self.updated_at)
        if self.visibility == 'WITHHELD_UNTIL_ANSWER_CLOSURE':
            if self.rows or self.next_cursor is not None or self.answer_acceptance_closed_at is not None:
                raise ValueError('Results disclosed before closure.')
        else:
            c.validate_timestamp(self.answer_acceptance_closed_at)
        keys = [(c.parse_timestamp(r.received_at), r.result_id) for r in self.rows]
        if keys != sorted(keys) or len({r.result_id for r in self.rows}) != len(self.rows):
            raise ValueError('Invalid result order.')
        return self


class EndpointChoiceAbandonment(_Frozen):
    schema_version: Literal['ln_church.agent_task_abandon_response.endpoint_choice_reason.v1', 'ln_church.agent_task_abandon_response.endpoint_choice_reason.v2']
    task_id: str
    execution_id: str
    state: Literal['abandoned']
    abandoned_at: str

    @model_validator(mode='after')
    def _check(self):
        c.validate_task_id(self.task_id); c.execution_id(self.execution_id); c.validate_timestamp(self.abandoned_at)
        return self


@dataclass(frozen=True)
class EndpointChoiceCompletionResult:
    state: Literal['accepted', 'unknown', 'rejected']
    receipt: Optional[EndpointChoiceCompletionReceipt] = None
    status: Optional[EndpointChoiceSubmissionStatus] = field(default=None, repr=False)
    error_code: Optional[str] = None
    post_requests: int = 0
    status_requests: int = 0
