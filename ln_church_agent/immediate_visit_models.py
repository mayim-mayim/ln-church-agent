"""Immutable, strict immediate visit wire values and private Claim capabilities."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any, Dict, Literal, Mapping, Optional, Tuple, Union

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
    task_type: Literal["immediate_http_visit.v1"]
    profile_id: Literal["immediate_visit_utf8.v1"]
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
        if not 1 <= len(self.endpoints) <= 10 or len({e.endpoint_id for e in self.endpoints}) != len(self.endpoints):
            raise ValueError("Invalid endpoints.")
        return self


class ImmediateVisitTask(_OfferSnapshot):
    schema_version: Literal["ln_church.agent_task.immediate_visit.v1"]
    definition_version: Literal["1.0.0"]
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


class ImmediateVisitTaskPage(_Frozen):
    schema_version: Literal["ln_church.agent_task_page.immediate_visit.v1"]
    tasks: Tuple[ImmediateVisitTask, ...]
    next_cursor: Optional[str]

    @field_validator("tasks", mode="before")
    @classmethod
    def _tasks(cls, value: Any) -> Any:
        if type(value) not in (list, tuple) or len(value) > 100:
            raise ValueError("Invalid task page.")
        return tuple(value)

    @field_validator("next_cursor")
    @classmethod
    def _cursor(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and (not value or len(value.encode("utf-8")) > 8192):
            raise ValueError("Invalid cursor.")
        return value


class ImmediateVisitClaimCredential(_OfferSnapshot):
    """Server Claim snapshot; bearer is absent from repr and ordinary serialization."""
    schema_version: Literal["ln_church.agent_task_claim_response.immediate_visit.v1"]
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
    schema_version: Literal["ln_church.task_completion.immediate_visit.v1"]
    task_id: str
    execution_id: str
    submission_id: str
    endpoint_id: str
    profile_id: Literal["immediate_visit_utf8.v1"]
    observation: ImmediateVisitObservation = Field(discriminator="outcome", repr=False)

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
    profile_id: Literal["immediate_visit_utf8.v1"]
    report_sha256: str = Field(repr=False)
    received_at: str

    @model_validator(mode="after")
    def _identity(self) -> "_ReceiptIdentity":
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
    schema_version: Literal["ln_church.task_completion_receipt.immediate_visit.v1"]
    status_url: str = Field(repr=False)
    receipt_state: Literal["accepted"]

    @model_validator(mode="after")
    def _status_link(self) -> "ImmediateVisitCompletionReceipt":
        if self.status_url != PUBLIC_API_ORIGIN + task_status_path(self.task_id, self.submission_id):
            raise ValueError("Invalid receipt status URL.")
        return self


class ImmediateVisitSubmissionStatus(_ReceiptIdentity):
    schema_version: Literal["ln_church.task_submission_status.immediate_visit.v1"]
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
    status: Optional[ImmediateVisitSubmissionStatus] = None
    error_code: Optional[str] = None
    post_requests: int = Field(default=0, ge=0)
    status_requests: int = Field(default=0, ge=0)


class _ImmediateVisitAbandonmentResponse(_Frozen):
    """Validate the accepted Hondō response without adding a public Wire schema."""
    schema_version: Literal["ln_church.agent_task_abandon_response.immediate_visit.v1"]
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
