"""Immutable, strict immediate visit wire values and private Claim capabilities."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Union, Any, Dict, Literal, Mapping, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, field_validator, model_validator

from .immediate_visit_contract import (
    AGENT_REASONS, STATUS_REASONS, TASK_TYPE, PROFILE_ID, TASK_SCHEMA_VERSION,
    TASK_PAGE_SCHEMA_VERSION, CLAIM_RESPONSE_SCHEMA_VERSION, COMPLETION_SCHEMA_VERSION,
    COMPLETION_RECEIPT_SCHEMA_VERSION, STATUS_SCHEMA_VERSION,
    canonical_report_bytes, decode_json_object, MAX_REPORT_BYTES, endpoint_id_for_url,
    validate_endpoint_url, validate_endpoint_id, validate_task_id, validate_opaque_id,
    validate_claim_token, validate_reward_address, validate_sha256, validate_submission_id,
    validate_timestamp, validate_transaction_hash, task_status_path, PUBLIC_API_ORIGIN,
)


class _Frozen(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except Exception:
            invalid = True
        if invalid:
            data.clear()
            raise ValueError("Invalid immediate visit wire value.")

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        invalid = False
        try:
            if isinstance(obj, cls):
                obj = obj.model_dump(mode="python")
            if not isinstance(obj, Mapping):
                raise ValueError
            if obj.get("schema_version", "").endswith(".v3_1"):
                cls = globals().get("_V31_MODELS", {}).get(cls, cls)
            return cls(**dict(obj))
        except Exception:
            invalid = True
        if invalid:
            raise ValueError("Invalid immediate visit wire value.")

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Any:
        invalid = False
        try:
            raw = json_data.encode("utf-8") if isinstance(json_data, str) else bytes(json_data)
            return cls.model_validate(decode_json_object(raw, 4 * 1024 * 1024))
        except Exception:
            invalid = True
        if invalid:
            raise ValueError("Invalid immediate visit wire value.")


class ImmediateVisitEndpoint(_Frozen):
    endpoint_id: str
    url: str = Field(repr=False)

    @model_validator(mode="after")
    def _binding(self) -> "ImmediateVisitEndpoint":
        if validate_endpoint_id(self.endpoint_id) != endpoint_id_for_url(self.url):
            raise ValueError("Invalid endpoint binding.")
        return self


class ImmediateVisitReward(_Frozen):
    network: Literal["eip155:8453"]
    asset: Literal["USDC"]
    asset_address: Literal["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"]
    base_amount_atomic: Literal["7500"]
    bonus_amount_atomic: Literal["7500"]
    maximum_amount_atomic: Literal["15000"]


class _OfferSnapshot(_Frozen):
    task_id: str
    task_type: Literal["immediate_http_visit.v1", "immediate_http_visit.v2", "immediate_http_visit.v3"]
    profile_id: Literal["immediate_visit_utf8.v1", "immediate_visit_utf8.v2", "immediate_visit_utf8.v3"]
    endpoints: Tuple[ImmediateVisitEndpoint, ...]
    repeat_policy: Literal["allow", "once_per_endpoint"]
    reward: ImmediateVisitReward

    @field_validator("task_id")
    @classmethod
    def _task(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("endpoints", mode="before")
    @classmethod
    def _endpoints(cls, value: Any) -> Any:
        if type(value) not in (list, tuple):
            raise ValueError("Invalid endpoints.")
        return tuple(item.model_dump(mode="python") if isinstance(item, ImmediateVisitEndpoint) else item for item in value)

    @field_validator("reward", mode="before")
    @classmethod
    def _reward(cls, value: Any) -> Any:
        return value.model_dump(mode="python") if isinstance(value, ImmediateVisitReward) else value

    @model_validator(mode="after")
    def _unique(self) -> "_OfferSnapshot":
        from .immediate_visit_versions import validate_tuple
        validate_tuple(self)
        if not 1 <= len(self.endpoints) <= 10 or len({e.endpoint_id for e in self.endpoints}) != len(self.endpoints):
            raise ValueError("Invalid endpoints.")
        return self


class ImmediateVisitTask(_OfferSnapshot):
    schema_version: Literal["ln_church.agent_task.immediate_visit.v1", "ln_church.agent_task.immediate_visit.v2", "ln_church.agent_task.immediate_visit.v3"]
    definition_version: Literal["1.0.0", "2.0.0", "3.0.0"]
    status: Literal["OPEN", "LISTING_ENDED", "CLOSED"]
    published_at: str
    listing_ends_at: str
    plan_id: Literal["C50", "C500", "C5000"]
    registration_amount_atomic: Literal["1000000", "10000000", "100000000"]
    capacity_total: int = Field(ge=0)
    capacity_reserved: int = Field(ge=0)
    capacity_consumed: int = Field(ge=0)
    capacity_available: int = Field(ge=0)
    definition_url: str = Field(repr=False)
    summary_url: str = Field(repr=False)
    results_url: str = Field(repr=False)

    @field_validator("published_at", "listing_ends_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return validate_timestamp(value, server=True)

    @field_validator("definition_url", "summary_url", "results_url")
    @classmethod
    def _official_link(cls, value: str) -> str:
        validate_endpoint_url(value)
        if not value.startswith(PUBLIC_API_ORIGIN + "/"):
            raise ValueError("Invalid official URL.")
        return value


    @model_validator(mode="after")
    def _listing_version(self):
        from datetime import timedelta
        from .immediate_visit_contract import parse_timestamp
        from .immediate_visit_versions import version_of
        version = version_of(self)
        if parse_timestamp(self.listing_ends_at) - parse_timestamp(self.published_at) != timedelta(hours=168 if version in ("v3", "v3_1") else 48):
            raise ValueError("Invalid listing duration.")
        if version == "v3" and self.definition_url != PUBLIC_API_ORIGIN + "/agent-task-specs/immediate_http_visit.v3/3.0.0/SKILL.md":
            raise ValueError("Invalid Immediate v3 definition URL.")
        return self


class ImmediateVisitTaskPage(_Frozen):
    schema_version: Literal["ln_church.agent_task_page.immediate_visit.v1", "ln_church.agent_task_page.immediate_visit.v2", "ln_church.agent_task_page.immediate_visit.v3"]
    tasks: Tuple[ImmediateVisitTask, ...]
    next_cursor: Optional[str]

    @field_validator("tasks", mode="before")
    @classmethod
    def _tasks(cls, value: Any) -> Any:
        if type(value) not in (list, tuple) or len(value) > 100:
            raise ValueError("Invalid task page.")
        return tuple(value)

    @model_validator(mode="after")
    def _page_version(self):
        version = self.schema_version.rsplit(".", 1)[1]
        if any(t.schema_version.rsplit(".", 1)[1] != version for t in self.tasks):
            raise ValueError("Cross-version page.")
        return self

    @field_validator("next_cursor")
    @classmethod
    def _cursor(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and (not value or len(value.encode("utf-8")) > 8192):
            raise ValueError("Invalid cursor.")
        return value


class ImmediateVisitClaimCredential(_OfferSnapshot):
    """Server Claim snapshot; bearer is absent from repr and ordinary serialization."""
    schema_version: Literal["ln_church.agent_task_claim_response.immediate_visit.v1", "ln_church.agent_task_claim_response.immediate_visit.v2", "ln_church.agent_task_claim_response.immediate_visit.v3"]
    execution_id: str
    claimed_at: str
    report_deadline: str
    reward_address: str = Field(repr=False)
    reward_address_control_verified: Literal[False]
    _claim_token: SecretStr = PrivateAttr()

    def __init__(self, **data: Any) -> None:
        raw_token = data.pop("claim_token", None)
        invalid = False
        try:
            token = validate_claim_token(raw_token)
            super().__init__(**data)
            self._claim_token = SecretStr(token)
        except Exception:
            invalid = True
        if invalid:
            data.clear()
            raw_token = None
            raise ValueError("Invalid immediate visit Claim credential.")

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "ImmediateVisitClaimCredential":
        if isinstance(obj, cls):
            return obj._validated_snapshot()
        if not isinstance(obj, Mapping):
            raise ValueError("Invalid immediate visit Claim credential.")
        if obj.get("schema_version", "").endswith(".v3_1"):
            cls = globals().get("_V31_MODELS", {}).get(cls, cls)
        return cls(**dict(obj))

    @field_validator("execution_id")
    @classmethod
    def _execution(cls, value: str) -> str:
        return validate_opaque_id(value, "execution_id")

    @field_validator("reward_address")
    @classmethod
    def _address(cls, value: str) -> str:
        return validate_reward_address(value)

    @field_validator("reward_address_control_verified", mode="before")
    @classmethod
    def _verified(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("Invalid address control verification.")
        return value

    @field_validator("claimed_at", "report_deadline")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return validate_timestamp(value, server=True)

    def _claim_token_value(self) -> str:
        return self._claim_token.get_secret_value()

    def _private_payload(self) -> Dict[str, Any]:
        payload = self.model_dump(mode="python")
        payload["claim_token"] = self._claim_token_value()
        return payload

    def _validated_snapshot(self) -> "ImmediateVisitClaimCredential":
        return type(self)(**self._private_payload())

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError("Private Claim credentials cannot be pickled.")

    def __getstate__(self) -> Any:
        raise TypeError("Private Claim credentials cannot be pickled.")


ImmediateVisitClaimResponse = ImmediateVisitClaimCredential


class _Observation(_Frozen):
    status: Optional[int]
    media_family: Optional[Literal["html", "json"]]
    body_bytes: Optional[int]
    fetch_started_at: Optional[str]
    fetch_finished_at: Optional[str]

    @field_validator("status")
    @classmethod
    def _status(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and not 100 <= value <= 599:
            raise ValueError("Invalid status.")
        return value

    @field_validator("body_bytes")
    @classmethod
    def _size(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 0:
            raise ValueError("Invalid body_bytes.")
        return value

    @field_validator("fetch_started_at", "fetch_finished_at")
    @classmethod
    def _time(cls, value: Optional[str]) -> Optional[str]:
        return validate_timestamp(value) if value is not None else None


class ImmediateVisitComparableObservation(_Observation):
    outcome: Literal["comparable"]
    status: int
    media_family: Literal["html", "json"]
    body_bytes: int
    fetch_started_at: str
    fetch_finished_at: str
    structure_sha256: str = Field(repr=False)
    body_sha256: str = Field(repr=False)

    @field_validator("structure_sha256", "body_sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        return validate_sha256(value)

    @model_validator(mode="after")
    def _comparable(self) -> "ImmediateVisitComparableObservation":
        if not 200 <= self.status <= 599 or self.status in (206, 304) or not 1 <= self.body_bytes <= 2097152:
            raise ValueError("Invalid comparable observation.")
        return self


class ImmediateVisitInconclusiveObservation(_Observation):
    outcome: Literal["inconclusive"]
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: str) -> str:
        if value not in AGENT_REASONS:
            raise ValueError("Invalid Agent observation reason.")
        return value


ImmediateVisitObservation = Union[ImmediateVisitComparableObservation, ImmediateVisitInconclusiveObservation]


class ImmediateVisitCompletionReport(_Frozen):
    schema_version: Literal["ln_church.task_completion.immediate_visit.v1", "ln_church.task_completion.immediate_visit.v2", "ln_church.task_completion.immediate_visit.v3", "ln_church.task_completion.immediate_visit.v3_1"]
    task_id: str
    execution_id: str
    submission_id: str
    endpoint_id: str
    profile_id: Literal["immediate_visit_utf8.v1", "immediate_visit_utf8.v2", "immediate_visit_utf8.v3"]
    observation: ImmediateVisitObservation = Field(discriminator="outcome", repr=False)

    @model_validator(mode="after")
    def _report_version(self):
        if self.schema_version.rsplit(".", 1)[1].split("_")[0] != self.profile_id.rsplit(".", 1)[1]:
            raise ValueError("Cross-version report.")
        return self

    @field_validator("task_id")
    @classmethod
    def _task(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("execution_id")
    @classmethod
    def _execution(cls, value: str) -> str:
        return validate_opaque_id(value, "execution_id")

    @field_validator("submission_id")
    @classmethod
    def _submission(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("endpoint_id")
    @classmethod
    def _endpoint(cls, value: str) -> str:
        return validate_endpoint_id(value)


@dataclass(frozen=True, init=False)
class FrozenImmediateVisitReport:
    """Entire validated JCS request, allocated before any POST; no bearer material."""
    canonical_bytes: bytes = field(repr=False)
    report_sha256: str = field(repr=False)

    def __init__(self, canonical_bytes: bytes) -> None:
        invalid = False
        try:
            raw = decode_json_object(canonical_bytes, MAX_REPORT_BYTES)
            parsed = ImmediateVisitCompletionReport.model_validate(raw)
            expected = canonical_report_bytes(parsed.model_dump(mode="json"))
            if expected != canonical_bytes:
                raise ValueError
        except Exception:
            invalid = True
        if invalid:
            raise ValueError("Invalid frozen immediate visit report.")
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(self, "report_sha256", hashlib.sha256(canonical_bytes).hexdigest())

    @classmethod
    def from_report(cls, report: Any) -> "FrozenImmediateVisitReport":
        invalid = False
        try:
            value = report.model_dump(mode="json") if isinstance(report, ImmediateVisitCompletionReport) else report
            parsed = ImmediateVisitCompletionReport.model_validate(value)
            return cls(canonical_report_bytes(parsed.model_dump(mode="json")))
        except Exception:
            invalid = True
        if invalid:
            raise ValueError("Invalid frozen immediate visit report.")

    @classmethod
    def from_bytes(cls, value: bytes) -> "FrozenImmediateVisitReport":
        return cls(value)

    @property
    def report(self) -> ImmediateVisitCompletionReport:
        return ImmediateVisitCompletionReport.model_validate(decode_json_object(self.canonical_bytes, MAX_REPORT_BYTES))

    @property
    def task_id(self) -> str:
        return self.report.task_id

    @property
    def execution_id(self) -> str:
        return self.report.execution_id

    @property
    def submission_id(self) -> str:
        return self.report.submission_id

    @property
    def endpoint_id(self) -> str:
        return self.report.endpoint_id

    @property
    def profile_id(self) -> str:
        return self.report.profile_id

    def to_completion_report(self) -> ImmediateVisitCompletionReport:
        return self.report


class _ReceiptIdentity(_Frozen):
    task_id: str
    execution_id: str
    submission_id: str
    endpoint_id: str
    profile_id: Literal["immediate_visit_utf8.v1", "immediate_visit_utf8.v2", "immediate_visit_utf8.v3"]
    report_sha256: str = Field(repr=False)
    received_at: str

    @model_validator(mode="after")
    def _identity(self) -> "_ReceiptIdentity":
        if self.schema_version.rsplit(".", 1)[1].split("_")[0] != self.profile_id.rsplit(".", 1)[1]:
            raise ValueError("Cross-version receipt.")
        validate_task_id(self.task_id)
        validate_opaque_id(self.execution_id, "execution_id")
        validate_submission_id(self.submission_id)
        validate_endpoint_id(self.endpoint_id)
        validate_sha256(self.report_sha256)
        validate_timestamp(self.received_at, server=True)
        return self

    def matches(self, report: FrozenImmediateVisitReport) -> bool:
        return all(getattr(self, name) == getattr(report, name) for name in (
            "task_id", "execution_id", "submission_id", "endpoint_id", "profile_id", "report_sha256"))


class ImmediateVisitCompletionReceipt(_ReceiptIdentity):
    schema_version: Literal["ln_church.task_completion_receipt.immediate_visit.v1", "ln_church.task_completion_receipt.immediate_visit.v2", "ln_church.task_completion_receipt.immediate_visit.v3", "ln_church.task_completion_receipt.immediate_visit.v3_1"]
    status_url: str = Field(repr=False)
    receipt_state: Literal["accepted"]

    @model_validator(mode="after")
    def _status_link(self) -> "ImmediateVisitCompletionReceipt":
        if self.status_url != PUBLIC_API_ORIGIN + task_status_path(self.task_id, self.submission_id):
            raise ValueError("Invalid receipt status URL.")
        return self


class ImmediateVisitSubmissionStatus(_ReceiptIdentity):
    schema_version: Literal["ln_church.task_submission_status.immediate_visit.v1", "ln_church.task_submission_status.immediate_visit.v2", "ln_church.task_submission_status.immediate_visit.v3", "ln_church.task_submission_status.immediate_visit.v3_1"]
    evaluation_state: Literal["pending", "repeat_drop", "inconclusive", "mismatch", "base_approved", "base_bonus_approved"]
    decision_at: Optional[str]
    approved_amount_atomic: Literal["0", "7500", "15000"]
    bonus_approved: bool
    payment_state: Literal["not_applicable", "pending", "ambiguous", "paid_confirmed", "failed"]
    transaction_hash: Optional[str] = Field(repr=False)
    reason: Optional[str]
    updated_at: str

    @field_validator("decision_at", "updated_at")
    @classmethod
    def _timestamp(cls, value: Optional[str]) -> Optional[str]:
        return validate_timestamp(value, server=True) if value is not None else None

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in STATUS_REASONS:
            raise ValueError("Invalid status reason.")
        return value

    @field_validator("transaction_hash")
    @classmethod
    def _hash(cls, value: Optional[str]) -> Optional[str]:
        return validate_transaction_hash(value) if value is not None else None

    @model_validator(mode="after")
    def _state(self) -> "ImmediateVisitSubmissionStatus":
        expected = {"base_approved": "7500", "base_bonus_approved": "15000"}.get(self.evaluation_state, "0")
        if self.approved_amount_atomic != expected or self.bonus_approved != (self.evaluation_state == "base_bonus_approved"):
            raise ValueError("Invalid decision amount.")
        if (expected == "0") != (self.payment_state == "not_applicable"):
            raise ValueError("Invalid payment state.")
        if (self.evaluation_state == "pending") != (self.decision_at is None):
            raise ValueError("Invalid decision timestamp.")
        if self.payment_state == "paid_confirmed" and self.transaction_hash is None:
            raise ValueError("Missing payment confirmation hash.")
        return self


class ImmediateVisitCompletionResult(_Frozen):
    """Local finite helper result; accepted is a receipt, never inferred payment."""
    state: Literal["accepted", "unknown", "rejected"]
    receipt: Optional[ImmediateVisitCompletionReceipt] = None
    status: Optional[Union["ImmediateVisitStatusV31", ImmediateVisitSubmissionStatus]] = None
    error_code: Optional[str] = None
    post_requests: int = Field(default=0, ge=0)
    status_requests: int = Field(default=0, ge=0)


class _ImmediateVisitAbandonmentResponse(_Frozen):
    """Validate the accepted Hondō response without adding a public Wire schema."""
    schema_version: Literal["ln_church.agent_task_abandon_response.immediate_visit.v1", "ln_church.agent_task_abandon_response.immediate_visit.v2", "ln_church.agent_task_abandon_response.immediate_visit.v3", "ln_church.agent_task_abandon_response.immediate_visit.v3_1"]
    task_id: str
    execution_id: str
    state: Literal["abandoned"]
    abandoned_at: str

    @field_validator("abandoned_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return validate_timestamp(value, server=True)


class ImmediateVisitAbandonmentResult(_Frozen):
    """Local response observation; it does not fabricate an abandonment receipt."""
    transport_state: Literal["response_received", "unknown", "rejected"]
    task_id: str
    execution_id: str
    error_code: Optional[str] = None


class ImmediateVisitRewardV31(ImmediateVisitReward):
    asset_address: Literal['0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
                           '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913']
    base_amount_atomic: str
    bonus_amount_atomic: str
    maximum_amount_atomic: str

    @model_validator(mode='after')
    def _amounts(self):
        from ._contract_schema import validate_atomic_amount
        validate_atomic_amount(self.base_amount_atomic)
        validate_atomic_amount(self.bonus_amount_atomic, allow_zero=True)
        validate_atomic_amount(self.maximum_amount_atomic)
        if int(self.maximum_amount_atomic) != int(self.base_amount_atomic) + int(self.bonus_amount_atomic):
            raise ValueError('Invalid saved Immediate reward.')
        return self


def _immediate_terms(value):
    from ._contract_schema import (validate_economic_wire, validate_atomic_amount,
                                  validate_economic_revision, ECONOMIC_PACKS)
    validate_economic_wire('immediate', 'terms', value)
    validate_economic_revision(value['economic_terms_revision'])
    validate_atomic_amount(value['registration_amount_atomic'])
    validate_atomic_amount(value['maximum_reward_principal_atomic'])
    reward = ImmediateVisitRewardV31.model_validate(value['reward'])
    if (value['task_definition_digest'] != ECONOMIC_PACKS['immediate']['digest']
            or int(value['maximum_reward_principal_atomic']) != int(reward.maximum_amount_atomic) * value['capacity_total']
            or value['urls'] != [e['url'] for e in value['endpoints']]):
        raise ValueError('Invalid saved Immediate terms.')
    for endpoint in value['endpoints']:
        ImmediateVisitEndpoint.model_validate(endpoint)
    return value


class ImmediateVisitTaskV31(ImmediateVisitTask):
    schema_version: Literal['ln_church.agent_task.immediate_visit.v3_1']
    task_type: Literal['immediate_http_visit.v3']
    profile_id: Literal['immediate_visit_utf8.v3']
    definition_version: Literal['3.1.0']
    reward: ImmediateVisitRewardV31
    plan_id: str
    registration_amount_atomic: str
    economic_terms_revision: str
    terms_digest: str

    @model_validator(mode='after')
    def _economic(self):
        from ._contract_schema import validate_economic_wire, ECONOMIC_PACKS
        from .immediate_visit_profile import jcs_bytes
        p = self.model_dump(mode='json')
        validate_economic_wire('immediate', 'task', p)
        terms = {k: p[k] for k in ('task_type','plan_id','registration_amount_atomic',
                 'capacity_total','repeat_policy','reward','economic_terms_revision',
                 'definition_version','profile_id','endpoints')}
        terms.update(urls=[e['url'] for e in p['endpoints']],
                     task_definition_digest=ECONOMIC_PACKS['immediate']['digest'],
                     maximum_reward_principal_atomic=str(int(self.reward.maximum_amount_atomic) * self.capacity_total),
                     listing_seconds=604800, claim_seconds=600, reward_policy_id='IMMEDIATE_VISIT_REWARD_V1')
        _immediate_terms(terms)
        if (hashlib.sha256(jcs_bytes(terms)).hexdigest() != self.terms_digest
                or self.capacity_total != self.capacity_reserved + self.capacity_consumed + self.capacity_available
                or self.definition_url != PUBLIC_API_ORIGIN + '/agent-task-specs/immediate_http_visit.v3/3.1.0/SKILL.md'):
            raise ValueError('Invalid Immediate Task binding.')
        return self


class ImmediateVisitClaimV31(ImmediateVisitClaimCredential):
    schema_version: Literal['ln_church.agent_task_claim_response.immediate_visit.v3_1']
    task_type: Literal['immediate_http_visit.v3']
    profile_id: Literal['immediate_visit_utf8.v3']
    reward: ImmediateVisitRewardV31
    economic_terms_revision: str
    terms_digest: str
    terms_snapshot: Dict[str, Any] = Field(repr=False)

    @model_validator(mode='after')
    def _economic(self):
        from .immediate_visit_profile import jcs_bytes
        terms = _immediate_terms(self.terms_snapshot)
        if (hashlib.sha256(jcs_bytes(terms)).hexdigest() != self.terms_digest
                or any(self.model_dump(mode='json')[k] != terms[k] for k in
                       ('task_type','profile_id','endpoints','repeat_policy','reward','economic_terms_revision'))):
            raise ValueError('Invalid Immediate Claim binding.')
        return self


class ImmediateVisitPageV31(ImmediateVisitTaskPage):
    schema_version: Literal['ln_church.agent_task_page.immediate_visit.v3_1']
    tasks: Tuple[ImmediateVisitTaskV31, ...]


class ImmediateVisitStatusV31(ImmediateVisitSubmissionStatus):
    schema_version: Literal['ln_church.task_submission_status.immediate_visit.v3_1']
    approved_amount_atomic: str

    @model_validator(mode='after')
    def _state(self):
        from ._contract_schema import validate_atomic_amount, validate_economic_wire
        validate_economic_wire('immediate', 'result', self.model_dump(mode='json'))
        validate_atomic_amount(self.approved_amount_atomic, allow_zero=True)
        approved = self.evaluation_state in ('base_approved', 'base_bonus_approved')
        if (approved != (self.approved_amount_atomic != '0')
                or self.bonus_approved != (self.evaluation_state == 'base_bonus_approved')
                or (self.approved_amount_atomic == '0') != (self.payment_state == 'not_applicable')
                or (self.evaluation_state == 'pending') != (self.decision_at is None)
                or self.payment_state == 'paid_confirmed' and self.transaction_hash is None):
            raise ValueError('Invalid Immediate decision.')
        return self


_V31_MODELS = {ImmediateVisitTask: ImmediateVisitTaskV31,
               ImmediateVisitTaskPage: ImmediateVisitPageV31,
               ImmediateVisitClaimCredential: ImmediateVisitClaimV31,
               ImmediateVisitSubmissionStatus: ImmediateVisitStatusV31}

ImmediateVisitCompletionResult.model_rebuild()
