"""Strict typed models for the parallel v1.18 Task profile."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import uuid
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)

from .task_v2_contract import (
    ABANDON_REQUEST_SCHEMA_VERSION,
    CLAIM_REQUEST_SCHEMA_VERSION,
    CLAIM_RESPONSE_SCHEMA_VERSION,
    COMPLETION_RECEIPT_SCHEMA_VERSION,
    COMPLETION_SCHEMA_VERSION,
    CREDENTIAL_FILE_SCHEMA_VERSION,
    ERROR_SCHEMA_VERSION,
    MANIFEST_FETCH_OUTCOMES,
    PUBLIC_API_ORIGIN,
    READINESS_SCHEMA_VERSION,
    REWARD_STATUS_SCHEMA_VERSION,
    TARGET_OUTCOMES,
    TASK_DEFINITION_VERSION,
    TASK_PAGE_SCHEMA_VERSION,
    TASK_SCHEMA_VERSION,
    TASK_TYPE,
    canonical_completion_bytes,
    canonical_completion_digest,
    parse_rfc3339_whole_second,
    validate_agent_id,
    validate_amount_atomic,
    validate_claim_token,
    validate_elapsed_ms,
    validate_opaque_id,
    validate_release_url,
    validate_reward_address,
    validate_rfc3339_whole_second,
    validate_sha256,
    validate_submission_id,
    validate_task_id,
)


_STRICT = ConfigDict(
    strict=True,
    extra="forbid",
    hide_input_in_errors=True,
    str_strip_whitespace=False,
    validate_assignment=True,
)
_FROZEN = ConfigDict(**_STRICT, frozen=True)
_CREDENTIAL_HANDLE_DOMAIN = b"ln_church.task_v2_credential_handle.v1\x00"
_SECRET_PICKLE_ERROR = "Secret-bearing scheduled Task models cannot be pickled."

OfferStatus = Literal[
    "PENDING_SETTLEMENT",
    "OPEN",
    "CANCELLING",
    "ESTABLISHED",
    "RUNNING",
    "AGGREGATING",
    "CLOSED",
    "CANCELLED_OWNER",
    "CANCELLED_UNDER_THRESHOLD",
]
ReleaseState = Literal[
    "PENDING_ESTABLISHMENT", "PREPARING", "READY", "UNAVAILABLE"
]
ManifestFetchOutcome = Literal[
    "retrieved",
    "release_http_unexpected_status",
    "release_timeout",
    "release_dns_error",
    "release_tls_error",
    "release_connection_error",
    "release_protocol_error",
    "release_response_too_large",
    "release_encoding_unsupported",
    "release_invalid_json",
    "release_schema_invalid",
    "release_digest_mismatch",
    "release_interrupted",
]
TargetOutcome = Literal[
    "http_response",
    "dns_error",
    "tls_error",
    "connection_error",
    "timeout",
    "protocol_error",
    "interrupted_indeterminate",
    "not_attempted_interrupted",
    "not_attempted_deadline",
]


class _StrictModel(BaseModel):
    model_config = _STRICT


class _FrozenModel(BaseModel):
    model_config = _FROZEN


class _SecretBearingFrozenModel(_FrozenModel):
    """Frozen model whose private bearer values must never enter pickle."""

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError(_SECRET_PICKLE_ERROR)

    def __reduce__(self) -> Any:
        raise TypeError(_SECRET_PICKLE_ERROR)

    def __getstate__(self) -> Any:
        raise TypeError(_SECRET_PICKLE_ERROR)

    def __setstate__(self, state: Any) -> None:
        raise TypeError(_SECRET_PICKLE_ERROR)


def _finite_model_error(message: str) -> ValueError:
    return ValueError(message)


def _validate_nonnegative(value: Any, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("Invalid %s." % field_name)
    return value


class ScheduledTaskReward(_FrozenModel):
    network: Literal["eip155:8453"]
    asset: Literal["USDC"]
    asset_address: Literal["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"]
    amount_atomic: Literal["10000"]


class ScheduledHttpGetBatchTask(_FrozenModel):
    schema_version: Literal["ln_church.agent_task.v2"] = TASK_SCHEMA_VERSION
    task_id: str
    task_type: Literal["scheduled_http_get_batch.v1"] = TASK_TYPE
    task_definition_version: Literal["1.0.0"] = TASK_DEFINITION_VERSION
    task_definition_digest: str
    status: OfferStatus
    scheduled_at: str
    report_close_at: str
    plan_id: Literal["C50", "C500", "C5000"]
    capacity_total: int
    capacity_remaining: int
    minimum_counted_claims: int
    counted_claims_current: int
    successful_claims_lifetime: int
    active_reservations: int
    accepted_reports: int
    base_reward_entitlements: int
    base_rewards_paid_confirmed: int
    reference_bonus_state: str
    claimable: bool

    @field_validator("task_id")
    @classmethod
    def _task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _definition_digest(cls, value: str) -> str:
        return validate_sha256(value, "task_definition_digest")

    @field_validator("scheduled_at", "report_close_at")
    @classmethod
    def _timestamp(cls, value: str, info: Any) -> str:
        return validate_rfc3339_whole_second(value, info.field_name)

    @field_validator(
        "capacity_total",
        "capacity_remaining",
        "minimum_counted_claims",
        "counted_claims_current",
        "successful_claims_lifetime",
        "active_reservations",
        "accepted_reports",
        "base_reward_entitlements",
        "base_rewards_paid_confirmed",
        mode="before",
    )
    @classmethod
    def _counts(cls, value: Any, info: Any) -> int:
        return _validate_nonnegative(value, info.field_name)

    @field_validator("reference_bonus_state")
    @classmethod
    def _bonus_state(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 64
            or not all(char.isupper() or char.isdigit() or char == "_" for char in value)
        ):
            raise ValueError("Invalid reference_bonus_state.")
        return value

    @model_validator(mode="after")
    def _invariants(self) -> "ScheduledHttpGetBatchTask":
        expected_capacity = {"C50": 50, "C500": 500, "C5000": 5000}[self.plan_id]
        scheduled = parse_rfc3339_whole_second(self.scheduled_at, "scheduled_at")
        report_close = parse_rfc3339_whole_second(
            self.report_close_at, "report_close_at"
        )
        if (
            self.capacity_total != expected_capacity
            or self.minimum_counted_claims != expected_capacity // 2
            or self.capacity_remaining > self.capacity_total
            or self.base_rewards_paid_confirmed > self.base_reward_entitlements
            or self.accepted_reports > self.successful_claims_lifetime
            or report_close != scheduled + timedelta(seconds=600)
        ):
            raise ValueError("Invalid scheduled Task projection.")
        return self


class ScheduledHttpGetBatchTaskPage(_FrozenModel):
    schema_version: Literal["ln_church.agent_task_page.v1"] = TASK_PAGE_SCHEMA_VERSION
    tasks: List[ScheduledHttpGetBatchTask] = Field(max_length=50)
    next_cursor: Optional[str]

    @field_validator("next_cursor")
    @classmethod
    def _cursor(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 2048:
            raise ValueError("Invalid next_cursor.")
        return value


class ScheduledTaskClaimRequest(_FrozenModel):
    schema_version: Literal["ln_church.agent_task_claim_request.v1"] = (
        CLAIM_REQUEST_SCHEMA_VERSION
    )
    agent_id: str
    reward_address: str

    @field_validator("agent_id")
    @classmethod
    def _agent_id(cls, value: str) -> str:
        return validate_agent_id(value)

    @field_validator("reward_address")
    @classmethod
    def _reward_address(cls, value: str) -> str:
        return validate_reward_address(value)


class ScheduledTaskClaimResponse(_SecretBearingFrozenModel):
    """Transient Claim response whose two bearer values are private attrs."""

    schema_version: Literal["ln_church.agent_task_claim_response.v2"] = (
        CLAIM_RESPONSE_SCHEMA_VERSION
    )
    task_id: str
    task_type: Literal["scheduled_http_get_batch.v1"] = TASK_TYPE
    task_definition_version: Literal["1.0.0"] = TASK_DEFINITION_VERSION
    task_definition_digest: str
    claim_expires_at: str
    scheduled_at: str
    report_close_at: str
    manifest_url_not_before: str
    manifest_url_expires_at: str
    reward_address: str
    reward_address_control_verified: Literal[False]
    reward: ScheduledTaskReward
    _claim_token: SecretStr = PrivateAttr()
    _manifest_url: SecretStr = PrivateAttr()

    def __init__(self, **data: Any) -> None:
        raw_token = data.pop("claim_token", None)
        raw_url = data.pop("manifest_url", None)
        try:
            token = validate_claim_token(raw_token)
            release_url = validate_release_url(raw_url)
            super().__init__(**data)
        except Exception:
            data.clear()
            raw_token = None
            raw_url = None
            raise _finite_model_error("Invalid scheduled Task Claim response.") from None
        self._claim_token = SecretStr(token)
        self._manifest_url = SecretStr(release_url)
        raw_token = None
        raw_url = None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "ScheduledTaskClaimResponse":
        if isinstance(obj, cls):
            return cls(**obj._private_payload())
        if not isinstance(obj, Mapping):
            raise _finite_model_error("Invalid scheduled Task Claim response.")
        candidate = dict(obj)
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise _finite_model_error("Invalid scheduled Task Claim response.") from None

    def _private_payload(self) -> Dict[str, Any]:
        payload = self.model_dump(mode="python")
        payload["claim_token"] = self._claim_token_value()
        payload["manifest_url"] = self._manifest_url_value()
        return payload

    def _claim_token_value(self) -> str:
        return self._claim_token.get_secret_value()

    def _manifest_url_value(self) -> str:
        return self._manifest_url.get_secret_value()

    @field_validator("task_id")
    @classmethod
    def _task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        return validate_sha256(value, "task_definition_digest")

    @field_validator(
        "claim_expires_at",
        "scheduled_at",
        "report_close_at",
        "manifest_url_not_before",
        "manifest_url_expires_at",
    )
    @classmethod
    def _time(cls, value: str, info: Any) -> str:
        return validate_rfc3339_whole_second(value, info.field_name)

    @field_validator("reward_address")
    @classmethod
    def _address(cls, value: str) -> str:
        return validate_reward_address(value)

    @model_validator(mode="after")
    def _time_binding(self) -> "ScheduledTaskClaimResponse":
        scheduled = parse_rfc3339_whole_second(self.scheduled_at, "scheduled_at")
        report_close = parse_rfc3339_whole_second(
            self.report_close_at, "report_close_at"
        )
        if (
            self.manifest_url_not_before != self.scheduled_at
            or self.manifest_url_expires_at != self.report_close_at
            or self.claim_expires_at != self.report_close_at
            or report_close != scheduled + timedelta(seconds=600)
        ):
            raise ValueError("Invalid Claim time binding.")
        return self

    def to_credential(self, *, agent_id: str) -> "ScheduledTaskClaimCredential":
        return ScheduledTaskClaimCredential(
            api_origin=PUBLIC_API_ORIGIN,
            task_id=self.task_id,
            task_type=self.task_type,
            task_definition_version=self.task_definition_version,
            task_definition_digest=self.task_definition_digest,
            agent_id=validate_agent_id(agent_id),
            reward_address=self.reward_address,
            reward=self.reward.model_dump(mode="python"),
            claim_expires_at=self.claim_expires_at,
            scheduled_at=self.scheduled_at,
            report_close_at=self.report_close_at,
            manifest_url_not_before=self.manifest_url_not_before,
            manifest_url_expires_at=self.manifest_url_expires_at,
            claim_token=self._claim_token_value(),
            manifest_url=self._manifest_url_value(),
        )


class ScheduledTaskClaimCredential(_SecretBearingFrozenModel):
    """Private-file capability; ordinary serialization contains no bearer."""

    api_origin: Literal["https://kari.mayim-mayim.com"] = PUBLIC_API_ORIGIN
    task_id: str
    task_type: Literal["scheduled_http_get_batch.v1"] = TASK_TYPE
    task_definition_version: Literal["1.0.0"] = TASK_DEFINITION_VERSION
    task_definition_digest: str
    agent_id: str
    reward_address: str
    reward: ScheduledTaskReward
    claim_expires_at: str
    scheduled_at: str
    report_close_at: str
    manifest_url_not_before: str
    manifest_url_expires_at: str
    _claim_token: SecretStr = PrivateAttr()
    _manifest_url: SecretStr = PrivateAttr()
    _bound_snapshot: Tuple[Any, ...] = PrivateAttr()
    _token_digest: bytes = PrivateAttr()

    def __init__(self, **data: Any) -> None:
        raw_token = data.pop("claim_token", None)
        raw_url = data.pop("manifest_url", None)
        try:
            token = validate_claim_token(raw_token)
            release_url = validate_release_url(raw_url)
            super().__init__(**data)
        except Exception:
            data.clear()
            raw_token = None
            raw_url = None
            raise _finite_model_error("Invalid scheduled Task credential.") from None
        self._claim_token = SecretStr(token)
        self._manifest_url = SecretStr(release_url)
        self._bound_snapshot = self._public_snapshot()
        self._token_digest = hashlib.sha256(token.encode("ascii")).digest()
        raw_token = None
        raw_url = None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "ScheduledTaskClaimCredential":
        if isinstance(obj, cls):
            return obj._validated_snapshot()
        if not isinstance(obj, Mapping):
            raise _finite_model_error("Invalid scheduled Task credential.")
        candidate = dict(obj)
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise _finite_model_error("Invalid scheduled Task credential.") from None

    @field_validator("task_id")
    @classmethod
    def _task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        return validate_sha256(value, "task_definition_digest")

    @field_validator("agent_id")
    @classmethod
    def _agent(cls, value: str) -> str:
        return validate_agent_id(value)

    @field_validator("reward_address")
    @classmethod
    def _address(cls, value: str) -> str:
        return validate_reward_address(value)

    @field_validator(
        "claim_expires_at",
        "scheduled_at",
        "report_close_at",
        "manifest_url_not_before",
        "manifest_url_expires_at",
    )
    @classmethod
    def _time(cls, value: str, info: Any) -> str:
        return validate_rfc3339_whole_second(value, info.field_name)

    @model_validator(mode="after")
    def _binding(self) -> "ScheduledTaskClaimCredential":
        scheduled = parse_rfc3339_whole_second(self.scheduled_at, "scheduled_at")
        report_close = parse_rfc3339_whole_second(
            self.report_close_at, "report_close_at"
        )
        if (
            self.claim_expires_at != self.report_close_at
            or self.manifest_url_not_before != self.scheduled_at
            or self.manifest_url_expires_at != self.report_close_at
            or report_close != scheduled + timedelta(seconds=600)
        ):
            raise ValueError("Invalid credential time binding.")
        return self

    def _claim_token_value(self) -> str:
        return self._claim_token.get_secret_value()

    def _manifest_url_value(self) -> str:
        return self._manifest_url.get_secret_value()

    def _public_snapshot(self) -> Tuple[Any, ...]:
        return (
            self.api_origin,
            self.task_id,
            self.task_type,
            self.task_definition_version,
            self.task_definition_digest,
            self.agent_id,
            self.reward_address,
            tuple(self.reward.model_dump(mode="python").items()),
            self.claim_expires_at,
            self.scheduled_at,
            self.report_close_at,
            self.manifest_url_not_before,
            self.manifest_url_expires_at,
        )

    def _local_fingerprint(self) -> str:
        snapshot = self._validated_snapshot()
        token = snapshot._claim_token_value()
        try:
            return hashlib.sha256(
                _CREDENTIAL_HANDLE_DOMAIN + token.encode("ascii")
            ).hexdigest()
        finally:
            token = None

    @property
    def local_claim_credential_handle(self) -> str:
        """Return the stable domain-separated, non-secret journal handle."""

        return self._local_fingerprint()

    def _validated_snapshot(self) -> "ScheduledTaskClaimCredential":
        token = self._claim_token_value()
        if self._public_snapshot() != self._bound_snapshot or not hmac.compare_digest(
            hashlib.sha256(token.encode("ascii")).digest(), self._token_digest
        ):
            token = None
            raise _finite_model_error("Invalid scheduled Task credential.")
        try:
            return type(self)(
                **self.model_dump(mode="python"),
                claim_token=token,
                manifest_url=self._manifest_url_value(),
            )
        finally:
            token = None

    def _to_private_file_payload(self) -> Dict[str, Any]:
        snapshot = self._validated_snapshot()
        payload = snapshot.model_dump(mode="json")
        payload.update(
            {
                "schema_version": CREDENTIAL_FILE_SCHEMA_VERSION,
                "state": "ACTIVE",
                "claim_token": snapshot._claim_token_value(),
                "manifest_url": snapshot._manifest_url_value(),
            }
        )
        return payload

    @classmethod
    def _from_private_file_payload(
        cls, payload: Mapping[str, Any]
    ) -> "ScheduledTaskClaimCredential":
        if not isinstance(payload, Mapping):
            raise _finite_model_error("Invalid scheduled Task credential file.")
        candidate = dict(payload)
        expected = set(cls.model_fields.keys()) | {
            "schema_version",
            "state",
            "claim_token",
            "manifest_url",
        }
        try:
            if set(candidate.keys()) != expected:
                raise ValueError
            if candidate.pop("schema_version") != CREDENTIAL_FILE_SCHEMA_VERSION:
                raise ValueError
            if candidate.pop("state") != "ACTIVE":
                raise ValueError
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise _finite_model_error("Invalid scheduled Task credential file.") from None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        comparison = datetime.now(timezone.utc) if now is None else now
        if not isinstance(comparison, datetime) or comparison.tzinfo is None:
            raise ValueError("Comparison time must be timezone-aware.")
        return parse_rfc3339_whole_second(
            self.claim_expires_at, "claim_expires_at"
        ) <= comparison.astimezone(timezone.utc)


class ScheduledTaskReadiness(_SecretBearingFrozenModel):
    """Finite readiness matrix; signed URL remains private."""

    schema_version: Literal["ln_church.agent_task_readiness.v1"] = (
        READINESS_SCHEMA_VERSION
    )
    task_id: str
    offer_status: OfferStatus
    execution_available: bool
    release_state: ReleaseState
    manifest_sha256: Optional[str] = None
    manifest_url_not_before: Optional[str] = None
    manifest_url_expires_at: str
    retry_at: Optional[str] = None
    new_target_start_before: Optional[str] = None
    report_close_at: Optional[str] = None
    _manifest_url: SecretStr = PrivateAttr()

    def __init__(self, **data: Any) -> None:
        raw_url = data.pop("manifest_url", None)
        try:
            release_url = validate_release_url(raw_url)
            super().__init__(**data)
        except Exception:
            data.clear()
            raw_url = None
            raise _finite_model_error("Invalid scheduled Task readiness.") from None
        self._manifest_url = SecretStr(release_url)
        raw_url = None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "ScheduledTaskReadiness":
        if isinstance(obj, cls):
            payload = obj.model_dump(mode="python")
            payload["manifest_url"] = obj._manifest_url_value()
            return cls(**payload)
        if not isinstance(obj, Mapping):
            raise _finite_model_error("Invalid scheduled Task readiness.")
        candidate = dict(obj)
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise _finite_model_error("Invalid scheduled Task readiness.") from None

    def _manifest_url_value(self) -> str:
        return self._manifest_url.get_secret_value()

    @field_validator("task_id")
    @classmethod
    def _task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("manifest_sha256")
    @classmethod
    def _digest(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else validate_sha256(value, "manifest_sha256")

    @field_validator(
        "manifest_url_not_before",
        "manifest_url_expires_at",
        "retry_at",
        "new_target_start_before",
        "report_close_at",
    )
    @classmethod
    def _time(cls, value: Optional[str], info: Any) -> Optional[str]:
        if value is None:
            return None
        return validate_rfc3339_whole_second(value, info.field_name)

    @model_validator(mode="after")
    def _matrix(self) -> "ScheduledTaskReadiness":
        post_t = self.manifest_sha256 is not None
        if post_t:
            if (
                self.offer_status not in {"ESTABLISHED", "RUNNING"}
                or self.retry_at is not None
                or self.new_target_start_before is None
                or self.report_close_at is None
                or self.release_state not in {"READY", "UNAVAILABLE"}
                or self.execution_available != (self.release_state == "READY")
            ):
                raise ValueError("Invalid post-T readiness state.")
            target_close = parse_rfc3339_whole_second(
                self.new_target_start_before, "new_target_start_before"
            )
            report_close = parse_rfc3339_whole_second(
                self.report_close_at, "report_close_at"
            )
            if target_close >= report_close:
                raise ValueError("Invalid post-T readiness state.")
        else:
            if (
                self.offer_status not in {"OPEN", "ESTABLISHED"}
                or self.execution_available
                or self.retry_at is None
                or self.manifest_url_not_before is None
                or self.new_target_start_before is not None
                or self.report_close_at is not None
                or self.release_state == "UNAVAILABLE"
            ):
                raise ValueError("Invalid pre-T readiness state.")
        return self


class ScheduledTaskAbandonRequest(_FrozenModel):
    schema_version: Literal["ln_church.agent_task_claim_abandon_request.v1"] = (
        ABANDON_REQUEST_SCHEMA_VERSION
    )
    abandonment_id: str

    @field_validator("abandonment_id")
    @classmethod
    def _abandonment_id(cls, value: str) -> str:
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("Invalid abandonment_id.") from None
        if str(parsed) != value:
            raise ValueError("Invalid abandonment_id.")
        return value


class ScheduledClaimAbandonmentResult(_FrozenModel):
    """SDK-local safe result; remote response text is deliberately discarded."""

    abandonment_id: str
    state: Literal["ABANDONED"] = "ABANDONED"
    terminal: Literal[True] = True

    @field_validator("abandonment_id")
    @classmethod
    def _abandonment_id(cls, value: str) -> str:
        return ScheduledTaskAbandonRequest(abandonment_id=value).abandonment_id


class ManifestFetchResult(_FrozenModel):
    outcome: ManifestFetchOutcome
    observed_sha256: Optional[str] = None
    http_status: Optional[int] = None
    elapsed_ms: Optional[int] = None

    @model_serializer(mode="wrap")
    def _wire_shape(self, handler: Any) -> Dict[str, Any]:
        return {
            key: value
            for key, value in handler(self).items()
            if value is not None
        }

    @field_validator("observed_sha256")
    @classmethod
    def _digest(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else validate_sha256(value, "observed_sha256")

    @field_validator("elapsed_ms", mode="before")
    @classmethod
    def _elapsed(cls, value: Optional[int]) -> Optional[int]:
        return None if value is None else validate_elapsed_ms(value, 5000, "elapsed_ms")

    @field_validator("http_status", mode="before")
    @classmethod
    def _status(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        if type(value) is not int or not 100 <= value <= 599:
            raise ValueError("Invalid http_status.")
        return value

    @model_validator(mode="after")
    def _presence(self) -> "ManifestFetchResult":
        if self.outcome not in MANIFEST_FETCH_OUTCOMES:
            raise ValueError("Invalid Manifest outcome.")
        if self.outcome == "retrieved":
            valid = self.http_status == 200 and self.observed_sha256 is not None
        elif self.outcome == "release_http_unexpected_status":
            valid = (
                self.http_status is not None
                and 201 <= self.http_status <= 599
                and self.observed_sha256 is None
            )
        elif self.outcome == "release_digest_mismatch":
            valid = self.http_status == 200 and self.observed_sha256 is not None
        else:
            valid = self.http_status is None and self.observed_sha256 is None
        if not valid:
            raise ValueError("Invalid Manifest outcome fields.")
        return self


class ScheduledTargetResult(_FrozenModel):
    position: int
    target_url: str
    outcome: TargetOutcome
    http_status: Optional[int] = None
    elapsed_ms: Optional[int] = None

    @model_serializer(mode="wrap")
    def _wire_shape(self, handler: Any) -> Dict[str, Any]:
        return {
            key: value
            for key, value in handler(self).items()
            if value is not None
        }

    @field_validator("position", mode="before")
    @classmethod
    def _position(cls, value: int) -> int:
        if type(value) is not int or value < 0 or value > 9:
            raise ValueError("Invalid target position.")
        return value

    @field_validator("target_url")
    @classmethod
    def _url(cls, value: str) -> str:
        from .task_v2_contract import validate_canonical_target_url

        return validate_canonical_target_url(value)

    @field_validator("elapsed_ms", mode="before")
    @classmethod
    def _elapsed(cls, value: Optional[int]) -> Optional[int]:
        return None if value is None else validate_elapsed_ms(value, 12000, "elapsed_ms")

    @field_validator("http_status", mode="before")
    @classmethod
    def _status(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        if type(value) is not int or not 200 <= value <= 599:
            raise ValueError("Invalid target http_status.")
        return value

    @model_validator(mode="after")
    def _presence(self) -> "ScheduledTargetResult":
        if self.outcome not in TARGET_OUTCOMES:
            raise ValueError("Invalid target outcome.")
        if (self.outcome == "http_response") != (self.http_status is not None):
            raise ValueError("Invalid target outcome fields.")
        return self


class ScheduledCompletionReport(_FrozenModel):
    schema_version: Literal["ln_church.scheduled_http_get_batch_completion.v1"] = (
        COMPLETION_SCHEMA_VERSION
    )
    submission_id: str
    task_type: Literal["scheduled_http_get_batch.v1"] = TASK_TYPE
    task_definition_version: Literal["1.0.0"] = TASK_DEFINITION_VERSION
    task_definition_digest: str
    manifest_sha256: str
    manifest_fetch: ManifestFetchResult
    results: List[ScheduledTargetResult] = Field(max_length=10)
    completed_at: str

    @field_validator("submission_id")
    @classmethod
    def _submission(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _definition_digest(cls, value: str) -> str:
        return validate_sha256(value, "task_definition_digest")

    @field_validator("manifest_sha256")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        return validate_sha256(value, "manifest_sha256")

    @field_validator("completed_at")
    @classmethod
    def _completed_at(cls, value: str) -> str:
        return validate_rfc3339_whole_second(value, "completed_at")

    @model_validator(mode="after")
    def _coverage(self) -> "ScheduledCompletionReport":
        if self.manifest_fetch.outcome == "retrieved":
            if not self.results:
                raise ValueError("Retrieved Manifest requires target results.")
            if [item.position for item in self.results] != list(range(len(self.results))):
                raise ValueError("Invalid target result order.")
        elif self.results:
            raise ValueError("Manifest failure forbids target results.")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_completion_bytes(
            self.model_dump(mode="json", exclude_none=True)
        )

    def canonical_digest(self) -> str:
        return canonical_completion_digest(
            self.model_dump(mode="json", exclude_none=True)
        )


class ScheduledCompletionReceipt(_FrozenModel):
    schema_version: Literal["ln_church.agent_task_completion_receipt.v2"] = (
        COMPLETION_RECEIPT_SCHEMA_VERSION
    )
    task_id: str
    task_type: Literal["scheduled_http_get_batch.v1"] = TASK_TYPE
    task_definition_version: Literal["1.0.0"] = TASK_DEFINITION_VERSION
    task_definition_digest: str
    manifest_sha256: str
    submission_id: str
    report_id: str
    report_sha256: str
    completion_id: str
    accepted_at: str
    receipt_state: Literal["DURABLY_ACCEPTED"]
    evaluation_state: str

    @field_validator("task_id")
    @classmethod
    def _task(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("task_definition_digest", "manifest_sha256", "report_sha256")
    @classmethod
    def _digest(cls, value: str, info: Any) -> str:
        return validate_sha256(value, info.field_name)

    @field_validator("submission_id")
    @classmethod
    def _submission(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("report_id", "completion_id")
    @classmethod
    def _opaque(cls, value: str, info: Any) -> str:
        return validate_opaque_id(value, info.field_name)

    @field_validator("accepted_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return validate_rfc3339_whole_second(value, "accepted_at")

    @field_validator("evaluation_state")
    @classmethod
    def _state(cls, value: str) -> str:
        if value not in {"PENDING", "APPROVED", "REJECTED", "BLOCKED"}:
            raise ValueError("Invalid evaluation_state.")
        return value


class ScheduledEvaluationStatus(_FrozenModel):
    state: Literal["PENDING", "APPROVED", "REJECTED", "BLOCKED"]
    reason: Optional[str] = None

    @field_validator("reason", mode="before")
    @classmethod
    def _reason(cls, value: Any) -> str:
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError("Invalid evaluation reason.")
        return value


SettlementState = Literal[
    "NOT_CREATED",
    "DUE",
    "SUBMITTING",
    "CONFIRMING",
    "PAID_CONFIRMED",
    "RETRYABLE_KNOWN_FAILURE",
    "AMBIGUOUS",
    "FAILED",
]


class ScheduledBaseRewardStatus(_FrozenModel):
    entitlement_state: Literal["NOT_CREATED", "DUE", "TERMINAL"]
    settlement_state: SettlementState


class ScheduledReferenceBonusStatus(_FrozenModel):
    candidate: bool
    decision_state: Literal["PENDING", "AWARDED", "NOT_AWARDED", "FAILED"]
    settlement_state: Optional[SettlementState] = None

    @field_validator("settlement_state", mode="before")
    @classmethod
    def _settlement(cls, value: Any) -> SettlementState:
        if value is None:
            raise ValueError("Invalid reference Bonus settlement state.")
        return value

    @model_validator(mode="after")
    def _decision_binding(self) -> "ScheduledReferenceBonusStatus":
        awarded = self.decision_state == "AWARDED"
        if awarded != (self.settlement_state is not None):
            raise ValueError("Invalid reference Bonus settlement binding.")
        return self


class ScheduledRewardStatus(_FrozenModel):
    schema_version: Literal["ln_church.agent_task_reward_status.v2"] = (
        REWARD_STATUS_SCHEMA_VERSION
    )
    task_id: str
    task_type: Literal["scheduled_http_get_batch.v1"] = TASK_TYPE
    task_definition_version: Literal["1.0.0"] = TASK_DEFINITION_VERSION
    task_definition_digest: str
    manifest_sha256: str
    submission_id: str
    report_id: str
    report_sha256: str
    accepted_at: str
    receipt_state: Literal["DURABLY_ACCEPTED"]
    evaluation: ScheduledEvaluationStatus
    base_reward: ScheduledBaseRewardStatus
    reference_bonus: ScheduledReferenceBonusStatus
    terminal: bool
    retry_after_seconds: int

    @field_validator("task_id")
    @classmethod
    def _task(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("task_definition_digest", "manifest_sha256", "report_sha256")
    @classmethod
    def _digest(cls, value: str, info: Any) -> str:
        return validate_sha256(value, info.field_name)

    @field_validator("submission_id")
    @classmethod
    def _submission(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("report_id")
    @classmethod
    def _report(cls, value: str) -> str:
        return validate_opaque_id(value, "report_id")

    @field_validator("accepted_at")
    @classmethod
    def _accepted(cls, value: str) -> str:
        return validate_rfc3339_whole_second(value, "accepted_at")

    @field_validator("retry_after_seconds", mode="before")
    @classmethod
    def _retry(cls, value: Any) -> int:
        if type(value) is not int or value < 0 or value > 3600:
            raise ValueError("Invalid retry_after_seconds.")
        return value

    @model_validator(mode="after")
    def _retry_terminal_binding(self) -> "ScheduledRewardStatus":
        if (self.retry_after_seconds == 0) != self.terminal:
            raise ValueError("Invalid terminal retry_after_seconds.")
        return self


class ScheduledCompletionAcknowledgement(_FrozenModel):
    source: Literal["receipt", "status"]
    receipt: Optional[ScheduledCompletionReceipt] = None
    status: Optional[ScheduledRewardStatus] = None

    @model_validator(mode="after")
    def _one_source(self) -> "ScheduledCompletionAcknowledgement":
        if self.source == "receipt":
            valid = self.receipt is not None and self.status is None
        else:
            valid = self.status is not None and self.receipt is None
        if not valid:
            raise ValueError("Invalid Completion acknowledgement.")
        return self


class ScheduledTaskErrorDetail(_FrozenModel):
    code: str
    message: str
    request_id: str
    retryable: bool

    @field_validator("code")
    @classmethod
    def _code(cls, value: str) -> str:
        from .task_v2_contract import V2_ERROR_CODES_BY_STATUS

        if value not in set().union(*V2_ERROR_CODES_BY_STATUS.values()):
            raise ValueError("Invalid v2 error code.")
        return value

    @field_validator("message", "request_id")
    @classmethod
    def _safe_text(cls, value: str, info: Any) -> str:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("Invalid %s." % info.field_name)
        return value


class ScheduledTaskErrorResponse(_FrozenModel):
    schema_version: Literal["ln_church.agent_task_error.v1"] = ERROR_SCHEMA_VERSION
    error: ScheduledTaskErrorDetail


__all__ = [
    "ScheduledHttpGetBatchTask",
    "ScheduledHttpGetBatchTaskPage",
    "ScheduledTaskReward",
    "ScheduledTaskClaimRequest",
    "ScheduledTaskClaimResponse",
    "ScheduledTaskClaimCredential",
    "ScheduledTaskReadiness",
    "ScheduledTaskAbandonRequest",
    "ScheduledClaimAbandonmentResult",
    "ManifestFetchResult",
    "ScheduledTargetResult",
    "ScheduledCompletionReport",
    "ScheduledCompletionReceipt",
    "ScheduledRewardStatus",
    "ScheduledCompletionAcknowledgement",
    "ScheduledTaskErrorResponse",
]
