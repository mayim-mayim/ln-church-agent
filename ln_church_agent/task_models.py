"""Strict public models for the v1.17.0 Agent Task Venue contract.

The models in this module are intentionally separate from the trusted internal
OpenClaw Domain Observation models.  Request models reject unknown fields.
Response models discard unknown fields and reconstruct only their finite
allowlist.
"""

from datetime import datetime, timezone
from enum import Enum
import copy
from functools import wraps
import hashlib
import hmac
import json
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from .task_contract import (
    CLAIM_LEASE_DURATION_SECONDS,
    CLAIM_REQUEST_SCHEMA_VERSION,
    CLAIM_RESPONSE_SCHEMA_VERSION,
    COMPLETION_REQUEST_SCHEMA_VERSION,
    COMPLETION_RESPONSE_SCHEMA_VERSION,
    CREDENTIAL_FILE_SCHEMA_VERSION,
    DEFAULT_TASK_DETAIL_LIMIT,
    ERROR_SCHEMA_VERSION,
    MAXIMUM_DISCOVERED_SURFACES,
    MAXIMUM_OBSERVATION_ERRORS,
    MAXIMUM_OBSERVED_URLS,
    MAXIMUM_TASK_DETAIL_LIMIT,
    MAXIMUM_TASK_LIST_LIMIT,
    MINIMUM_TASK_DETAIL_LIMIT,
    MINIMUM_TASK_LIST_LIMIT,
    OBSERVATION_RESPONSE_SCHEMA_VERSION,
    OBSERVATION_SUBMISSION_SCHEMA_VERSION,
    PUBLIC_API_ORIGIN,
    TASK_PAGE_SCHEMA_VERSION,
    TASK_SCHEMA_VERSION,
    TASK_TYPE_PAYMENT_SURFACE_DISCOVERY,
    canonical_submission_bytes,
    canonical_submission_digest,
    canonical_submission_digest_hex,
    claim_token_storage_digest,
    failure_codes_for_task_status,
    generate_submission_id,
    parse_rfc3339_utc,
    reward_state_for_task_status,
    task_detail_path,
    validate_agent_id,
    validate_amount_atomic,
    validate_claim_token,
    validate_cursor,
    validate_fixed_api_origin,
    validate_manifest_sha256,
    validate_manifest_url,
    validate_nfc_string,
    validate_observation_id,
    validate_public_domain,
    validate_public_observation_url,
    validate_reward_address,
    validate_rfc3339_utc,
    validate_submission_id,
    validate_task_definition_digest,
    validate_task_definition_version,
    validate_task_id,
    validate_transaction_hash,
)


TaskStatusValue = Literal["OPEN"]
TaskClaimStatusValue = Literal["CLAIMED"]
ExecutionTaskStatusValue = Literal[
    "SUBMITTED",
    "EVALUATION_REJECTED",
    "REWARD_PENDING",
    "REWARDED",
    "REWARD_FAILED",
    "REWARD_AMBIGUOUS",
]


RewardStateValue = Literal[
    "pending",
    "not_eligible",
    "approved_pending",
    "paid",
    "failed",
    "ambiguous",
]
PublicTaskFailureCodeValue = Literal[
    "observation_not_found",
    "claim_task_or_observation_binding_mismatch",
    "declared_agent_id_mismatch",
    "proven_observation_reuse",
    "settlement_retry_exhausted",
    "settlement_ambiguous",
    "settlement_conflict",
    "settlement_lease_expired",
    "settlement_unavailable",
]
TaskDomainObservationCheckpointStateValue = Literal[
    "REGISTER_PENDING", "REGISTERED"
]
TaskMethodValue = Literal["GET", "HEAD"]
MediaFamilyValue = Literal[
    "html", "json", "text", "image", "other", "unknown"
]
SurfaceTypeValue = Literal[
    "http_402", "x402", "l402", "mpp", "agent_commerce", "unknown"
]
ObservationStageValue = Literal[
    "dns", "connect", "tls", "request", "response", "validation"
]
ObservationErrorCodeValue = Literal[
    "timeout",
    "dns_failure",
    "connection_failure",
    "tls_failure",
    "http_error",
    "response_too_large",
    "unsupported_content",
    "invalid_public_target",
    "unknown",
]
PublicTaskErrorCodeValue = Literal[
    "invalid_request",
    "unsupported_task_type",
    "domain_mismatch",
    "claim_token_invalid",
    "task_not_found",
    "task_not_open",
    "task_state_conflict",
    "submission_conflict",
    "claim_lease_expired",
    "payload_too_large",
    "rate_limited",
    "internal_error",
]


class AgentTaskStatus(str, Enum):
    OPEN = "OPEN"


class AgentTaskClaimStatus(str, Enum):
    CLAIMED = "CLAIMED"


class AgentTaskSubmissionStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    EVALUATION_REJECTED = "EVALUATION_REJECTED"
    REWARD_PENDING = "REWARD_PENDING"
    REWARDED = "REWARDED"
    REWARD_FAILED = "REWARD_FAILED"
    REWARD_AMBIGUOUS = "REWARD_AMBIGUOUS"


class AgentTaskRewardState(str, Enum):
    PENDING = "pending"
    NOT_ELIGIBLE = "not_eligible"
    APPROVED_PENDING = "approved_pending"
    PAID = "paid"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


class TaskDomainObservationCheckpointState(str, Enum):
    """Finite SDK-local restart states for the guided Task bridge."""

    REGISTER_PENDING = "REGISTER_PENDING"
    REGISTERED = "REGISTERED"


_COMMON_CONFIG = ConfigDict(
    strict=True,
    hide_input_in_errors=True,
    str_strip_whitespace=False,
    validate_assignment=True,
)


def _require_exact_bool(value: Any, expected: bool, field_name: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("Invalid %s." % field_name)
    return value


def _require_exact_int(value: Any, expected: int, field_name: str) -> int:
    if type(value) is not int or value != expected:
        raise ValueError("Invalid %s." % field_name)
    return value


def _finite_validation_boundary(
    message: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Drop validation exception graphs and secret-bearing call arguments."""

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except Exception:
                pass
            args = ()
            kwargs.clear()
            raise ValueError(message)

        return wrapped

    return decorate


class _StrictRequestModel(BaseModel):
    model_config = ConfigDict(**_COMMON_CONFIG, extra="forbid")


class _StrictResponseModel(BaseModel):
    # A server may add response fields.  Ignoring extras reconstructs only the
    # finite public field allowlist and prevents accidental disclosure.
    model_config = ConfigDict(**_COMMON_CONFIG, extra="ignore")


_FROZEN_REQUEST_CONFIG = ConfigDict(
    strict=True,
    hide_input_in_errors=True,
    str_strip_whitespace=False,
    extra="forbid",
    frozen=True,
)

_FROZEN_RESPONSE_CONFIG = ConfigDict(
    strict=True,
    hide_input_in_errors=True,
    str_strip_whitespace=False,
    extra="ignore",
    frozen=True,
)

_TASK_DOMAIN_OBSERVATION_CHECKPOINT_SCHEMA_VERSION = (
    "ln_church.task_domain_observation_checkpoint.v1"
)
_TASK_DOMAIN_OBSERVATION_GUIDED_RESULT_SCHEMA_VERSION = (
    "ln_church.task_domain_observation_guided_result.v1"
)
_TASK_CREDENTIAL_FINGERPRINT_DOMAIN_SEPARATOR = (
    b"ln_church.task_guided_checkpoint.v1\x00"
)


def _strict_snapshot_value(value: Any) -> Any:
    """Recursively materialize model state so strict validation cannot reuse it."""

    if isinstance(value, BaseModel):
        return _strict_snapshot_value(dict(vars(value)))
    if type(value) is dict:
        return {
            copy.deepcopy(key): _strict_snapshot_value(item)
            for key, item in value.items()
        }
    if type(value) is list:
        return [_strict_snapshot_value(item) for item in value]
    if type(value) is tuple:
        return tuple(_strict_snapshot_value(item) for item in value)
    return copy.deepcopy(value)


def _exact_model_snapshot(
    value: Any,
    model_type: Any,
    message: str,
) -> Any:
    """Detach one nested helper value without silently dropping extras."""

    try:
        payload = _strict_snapshot_value(value)
        if (
            type(payload) is not dict
            or set(payload) != set(model_type.model_fields)
        ):
            raise ValueError
        return model_type.model_validate(payload, strict=True)
    except Exception:
        raise ValueError(message) from None


class TaskDefinitionReference(_StrictRequestModel):
    """Exact immutable reference to one server-selected Task Definition."""

    model_config = _FROZEN_REQUEST_CONFIG

    task_definition_version: str
    task_definition_digest: str
    manifest_url: str
    manifest_sha256: str
    _bound_values: tuple = PrivateAttr()
    _sealed: bool = PrivateAttr(default=False)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._bound_values = (
            self.task_definition_version,
            self.task_definition_digest,
            self.manifest_url,
            self.manifest_sha256,
        )
        self._sealed = True

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("Task Definition reference is immutable.")
        super().__setattr__(name, value)

    @field_validator("task_definition_version")
    @classmethod
    def _validate_definition_version(cls, value: str) -> str:
        return validate_task_definition_version(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _validate_definition_digest(cls, value: str) -> str:
        return validate_task_definition_digest(value)

    @field_validator("manifest_url")
    @classmethod
    def _validate_manifest_url(cls, value: str) -> str:
        return validate_manifest_url(value)

    @field_validator("manifest_sha256")
    @classmethod
    def _validate_manifest_sha256(cls, value: str) -> str:
        return validate_manifest_sha256(value)

    def _validated_snapshot(self) -> "TaskDefinitionReference":
        current = (
            self.task_definition_version,
            self.task_definition_digest,
            self.manifest_url,
            self.manifest_sha256,
        )
        if current != self._bound_values:
            raise ValueError("Invalid Task Definition reference.")
        try:
            return type(self)(
                task_definition_version=current[0],
                task_definition_digest=current[1],
                manifest_url=current[2],
                manifest_sha256=current[3],
            )
        except Exception:
            raise ValueError("Invalid Task Definition reference.") from None


class _TaskDefinitionFieldsModel(_StrictResponseModel):
    """Flattened wire fields with a typed immutable local view."""

    task_definition_version: str
    task_definition_digest: str
    manifest_url: str
    manifest_sha256: str

    @field_validator("task_definition_version")
    @classmethod
    def _validate_definition_version(cls, value: str) -> str:
        return validate_task_definition_version(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _validate_definition_digest(cls, value: str) -> str:
        return validate_task_definition_digest(value)

    @field_validator("manifest_url")
    @classmethod
    def _validate_manifest_url(cls, value: str) -> str:
        return validate_manifest_url(value)

    @field_validator("manifest_sha256")
    @classmethod
    def _validate_manifest_sha256(cls, value: str) -> str:
        return validate_manifest_sha256(value)

    @property
    def task_definition(self) -> TaskDefinitionReference:
        return TaskDefinitionReference(
            task_definition_version=self.task_definition_version,
            task_definition_digest=self.task_definition_digest,
            manifest_url=self.manifest_url,
            manifest_sha256=self.manifest_sha256,
        )


class AgentTaskConstraints(_StrictResponseModel):
    allowed_methods: List[TaskMethodValue] = Field(min_length=2, max_length=2)
    no_login: Literal[True]
    no_forms: Literal[True]
    no_vulnerability_scan: Literal[True]
    no_payment_to_target: Literal[True]

    @field_validator(
        "no_login",
        "no_forms",
        "no_vulnerability_scan",
        "no_payment_to_target",
        mode="before",
    )
    @classmethod
    def _validate_fixed_true(cls, value: Any) -> bool:
        return _require_exact_bool(value, True, "public-safe constraint")

    @field_validator("allowed_methods")
    @classmethod
    def _validate_allowed_methods(
        cls, value: List[TaskMethodValue]
    ) -> List[TaskMethodValue]:
        if value != ["GET", "HEAD"]:
            raise ValueError("Invalid task allowed_methods.")
        return value


class AgentTaskRewardTerms(_StrictResponseModel):
    model_config = _FROZEN_RESPONSE_CONFIG

    network: Literal["eip155:8453"]
    asset: Literal["USDC"]
    asset_address: Literal[
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    ]
    amount_atomic: str

    @field_validator("amount_atomic")
    @classmethod
    def _validate_amount_atomic(cls, value: str) -> str:
        return validate_amount_atomic(value)


class AgentTaskPocTerms(_StrictResponseModel):
    """Canonical experimental reward-delivery disclosure from Hondo."""

    model_config = _FROZEN_RESPONSE_CONFIG

    completion_2xx_meaning: Literal["durable_receipt_only"]
    completion_2xx_implies_evaluation_approval: Literal[False]
    completion_2xx_implies_payment_completion: Literal[False]
    payout_mode: Literal[
        "automatic_best_effort_with_finite_retry_and_recorded_evidence"
    ]
    payment_completion_sla: Literal[False]
    individual_investigation: Literal[False]
    manual_resend: Literal[False]
    compensation: Literal[False]
    alternative_payment: Literal[False]
    arbitrary_non_payment_authorized: Literal[False]
    required_public_surfaces: List[
        Literal[
            "task_get",
            "task_definition",
            "openapi_and_agent_documentation",
            "taskboard",
            "sdk_documentation",
        ]
    ] = Field(min_length=5, max_length=5)

    @field_validator(
        "completion_2xx_implies_evaluation_approval",
        "completion_2xx_implies_payment_completion",
        "payment_completion_sla",
        "individual_investigation",
        "manual_resend",
        "compensation",
        "alternative_payment",
        "arbitrary_non_payment_authorized",
        mode="before",
    )
    @classmethod
    def _validate_fixed_false(cls, value: Any) -> bool:
        return _require_exact_bool(value, False, "poc_terms disclosure")

    @field_validator("required_public_surfaces")
    @classmethod
    def _validate_required_public_surfaces(
        cls,
        value: List[str],
    ) -> List[str]:
        if value != [
            "task_get",
            "task_definition",
            "openapi_and_agent_documentation",
            "taskboard",
            "sdk_documentation",
        ]:
            raise ValueError("Invalid poc_terms required_public_surfaces.")
        return value


def _validate_public_submission_projection(
    *,
    task_status: str,
    reward_state: str,
    reward_tx_hash: Optional[str],
    rewarded_at: Optional[str],
    failure_code: Optional[str],
    evaluated_at: Optional[str] = None,
    require_evaluated_at_field: bool = True,
) -> None:
    """Enforce the exact public Submission status/evidence projection."""

    if reward_state != reward_state_for_task_status(task_status):
        raise ValueError("Task status and reward state do not match.")

    allowed_failure_codes = failure_codes_for_task_status(task_status)
    if allowed_failure_codes:
        if failure_code not in allowed_failure_codes:
            raise ValueError("Invalid Task failure_code for status.")
    elif failure_code is not None:
        raise ValueError("Task status must not include failure_code.")

    if require_evaluated_at_field:
        if task_status == "SUBMITTED":
            if evaluated_at is not None:
                raise ValueError(
                    "Submitted Task status must not include evaluated_at."
                )
        elif evaluated_at is None:
            raise ValueError(
                "Evaluated Task status requires evaluated_at."
            )

    if task_status == "REWARDED":
        if reward_tx_hash is None or rewarded_at is None:
            raise ValueError(
                "Paid reward status requires transaction metadata."
            )
    elif task_status == "REWARD_AMBIGUOUS":
        if rewarded_at is not None:
            raise ValueError(
                "Ambiguous reward status must not include rewarded_at."
            )
    elif reward_tx_hash is not None or rewarded_at is not None:
        raise ValueError(
            "Task status must not include transaction metadata."
        )


class AgentTaskExecutionSummary(_StrictResponseModel):
    """Exact public-safe durable Submission projection on Task detail."""

    # Summary rows have an exact public projection.  In particular, silently
    # accepting an internal execution identifier or credential field would
    # conceal a server-side privacy regression.
    model_config = _FROZEN_REQUEST_CONFIG

    submission_id: str
    observation_id: str
    task_status: ExecutionTaskStatusValue
    reward_state: RewardStateValue
    network: Literal["eip155:8453"]
    asset: Literal["USDC"]
    asset_address: Literal[
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    ]
    amount_atomic: str
    evaluated_at: Optional[str]
    reward_tx_hash: Optional[str]
    rewarded_at: Optional[str]
    failure_code: Optional[PublicTaskFailureCodeValue]

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("observation_id")
    @classmethod
    def _validate_observation_id(cls, value: str) -> str:
        return validate_observation_id(value)

    @field_validator("amount_atomic")
    @classmethod
    def _validate_amount_atomic(cls, value: str) -> str:
        return validate_amount_atomic(value)

    @field_validator("evaluated_at")
    @classmethod
    def _validate_optional_evaluated_at(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        return validate_rfc3339_utc(value, "evaluated_at")

    @field_validator("reward_tx_hash")
    @classmethod
    def _validate_optional_transaction_hash(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        value = validate_transaction_hash(value)
        if value != value.lower():
            raise ValueError("Invalid reward_tx_hash.")
        return value

    @field_validator("rewarded_at")
    @classmethod
    def _validate_optional_rewarded_at(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        return validate_rfc3339_utc(value, "rewarded_at")

    @model_validator(mode="after")
    def _validate_summary_invariants(self) -> "AgentTaskExecutionSummary":
        _validate_public_submission_projection(
            task_status=self.task_status,
            reward_state=self.reward_state,
            reward_tx_hash=self.reward_tx_hash,
            rewarded_at=self.rewarded_at,
            failure_code=self.failure_code,
            evaluated_at=self.evaluated_at,
        )
        return self


class _AgentTaskOfferProjection(_TaskDefinitionFieldsModel):
    """Common server-provided Task Offer fields for list and detail."""

    model_config = _FROZEN_RESPONSE_CONFIG

    schema_version: Literal["ln_church.agent_task.v1"]
    task_id: str
    task_type: Literal["payment_surface_discovery.v1"]
    status: Literal["OPEN"]
    seed_urls: List[str] = Field(max_length=0)
    observation_profile: Literal["public_safe_light"]
    constraints: AgentTaskConstraints
    reward: AgentTaskRewardTerms
    created_at: str
    expires_at: str
    active_execution_count: int
    claim_count_total: int
    rewarded_execution_count: int
    reward_paid_total_minor: int
    capacity_total: int
    capacity_remaining: int
    maximum_reward_principal_atomic: str
    claimable: bool
    poc_terms: AgentTaskPocTerms

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("seed_urls")
    @classmethod
    def _validate_seed_urls(cls, value: List[str]) -> List[str]:
        if value != []:
            raise ValueError("Invalid Task seed_urls.")
        return value

    @field_validator("created_at", "expires_at")
    @classmethod
    def _validate_required_timestamp(cls, value: str) -> str:
        return validate_rfc3339_utc(value)

    @field_validator(
        "active_execution_count",
        "claim_count_total",
        "rewarded_execution_count",
        "reward_paid_total_minor",
        "capacity_total",
        "capacity_remaining",
        mode="before",
    )
    @classmethod
    def _validate_aggregate_integer(cls, value: Any) -> int:
        if type(value) is not int:
            raise ValueError("Invalid Task Offer aggregate.")
        return value

    @field_validator("maximum_reward_principal_atomic")
    @classmethod
    def _validate_maximum_reward_principal_atomic(cls, value: str) -> str:
        return validate_amount_atomic(value)

    @field_validator("claimable", mode="before")
    @classmethod
    def _validate_claimable(cls, value: Any) -> bool:
        if type(value) is not bool:
            raise ValueError("Invalid Task Offer claimable snapshot.")
        return value

    @model_validator(mode="after")
    def _validate_task_invariants(self) -> "_AgentTaskOfferProjection":
        if (
            self.active_execution_count not in {0, 1}
            or self.claim_count_total < 0
            or self.capacity_total <= 0
            or self.rewarded_execution_count < 0
            or self.capacity_remaining < 0
            or self.reward_paid_total_minor < 0
        ):
            raise ValueError("Invalid Task Offer aggregate.")
        return self

    @property
    def task_url(self) -> str:
        return task_detail_path(self.task_id)


class AgentTaskListItem(_AgentTaskOfferProjection):
    """One common Task Offer projection returned by Task list."""


class AgentTask(_AgentTaskOfferProjection):
    """Task detail plus one server-provided Execution-summary page."""

    execution_summaries: List[AgentTaskExecutionSummary] = Field(
        max_length=MAXIMUM_TASK_DETAIL_LIMIT
    )
    execution_summaries_next_cursor: Optional[str]

    @field_validator("execution_summaries_next_cursor")
    @classmethod
    def _validate_execution_summaries_next_cursor(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        return validate_cursor(value)


# Explicit discoverable name for callers that distinguish list items from
# Task detail while preserving the existing package-level ``AgentTask`` name.
AgentTaskDetail = AgentTask


class AgentTaskPage(_StrictResponseModel):
    schema_version: Literal["ln_church.agent_task_page.v1"]
    tasks: List[AgentTaskListItem] = Field(max_length=MAXIMUM_TASK_LIST_LIMIT)
    next_cursor: Optional[str]

    @field_validator("next_cursor")
    @classmethod
    def _validate_next_cursor(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_cursor(value)


class AgentTaskListQuery(_StrictRequestModel):
    task_type: Literal[
        "payment_surface_discovery.v1"
    ] = TASK_TYPE_PAYMENT_SURFACE_DISCOVERY
    status: TaskStatusValue = "OPEN"
    limit: int = Field(
        default=20,
        ge=MINIMUM_TASK_LIST_LIMIT,
        le=MAXIMUM_TASK_LIST_LIMIT,
    )
    cursor: Optional[str] = None

    @field_validator("cursor")
    @classmethod
    def _validate_cursor(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_cursor(value)


class AgentTaskDetailQuery(_StrictRequestModel):
    """Only the existing bounded Task-detail summary query fields."""

    limit: int = Field(
        default=DEFAULT_TASK_DETAIL_LIMIT,
        ge=MINIMUM_TASK_DETAIL_LIMIT,
        le=MAXIMUM_TASK_DETAIL_LIMIT,
    )
    cursor: Optional[str] = None

    @field_validator("cursor")
    @classmethod
    def _validate_cursor(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return validate_cursor(value)


class AgentTaskClaimRequest(_StrictRequestModel):
    schema_version: Literal[
        "ln_church.agent_task_claim_request.v1"
    ] = CLAIM_REQUEST_SCHEMA_VERSION
    agent_id: str
    reward_address: str

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        return validate_agent_id(value)

    @field_validator("reward_address")
    @classmethod
    def _validate_reward_address(cls, value: str) -> str:
        return validate_reward_address(value)


class TaskClaimCredential(_TaskDefinitionFieldsModel):
    """Lease-bound bearer capability with secret-safe normal serialization."""

    model_config = _FROZEN_REQUEST_CONFIG

    api_origin: Literal["https://kari.mayim-mayim.com"] = PUBLIC_API_ORIGIN
    task_id: str
    task_type: Literal["payment_surface_discovery.v1"]
    agent_id: str
    reward_address: str
    reward: AgentTaskRewardTerms
    lease_expires_at: str
    _claim_token: SecretStr = PrivateAttr()
    _bound_public_snapshot: tuple = PrivateAttr()
    _claim_token_digest: bytes = PrivateAttr()
    _sealed: bool = PrivateAttr(default=False)

    @_finite_validation_boundary("Invalid task claim credential.")
    def __init__(self, **data: Any) -> None:
        # Pop and validate the capability before Pydantic sees the remaining
        # object.  Pydantic's structured ``ValidationError.errors()`` retains
        # raw field input even when ``hide_input_in_errors`` is enabled.  A
        # private SecretStr plus this finite pre-validation prevents both token
        # validation failures and unrelated field failures from retaining the
        # plaintext capability.
        raw_value = data.pop("claim_token", None)
        if isinstance(raw_value, SecretStr):
            raw_value = raw_value.get_secret_value()
        try:
            validated_token = validate_claim_token(raw_value)
        except (TypeError, ValueError):
            raw_value = None
            raise ValueError("Invalid task claim credential.") from None
        secret_token = SecretStr(validated_token)
        raw_value = None
        validated_token = None
        try:
            super().__init__(**data)
        except Exception:
            data.clear()
            raise ValueError("Invalid task claim credential.") from None
        self._claim_token = secret_token
        self._bound_public_snapshot = self._public_snapshot_tuple()
        self._claim_token_digest = claim_token_storage_digest(
            self._claim_token_value()
        )
        self._sealed = True

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("Task claim credential is immutable.")
        super().__setattr__(name, value)

    @classmethod
    @_finite_validation_boundary("Invalid task claim credential.")
    def model_validate(
        cls, obj: Any, **kwargs: Any
    ) -> "TaskClaimCredential":
        if isinstance(obj, cls):
            return obj._validated_snapshot()
        if not isinstance(obj, Mapping):
            raise ValueError("Invalid task claim credential.")
        # Route the public validation entry point through the custom
        # constructor so pydantic-core never retains the original secret-
        # bearing mapping as a root validation input.
        try:
            candidate = dict(obj)
        except Exception:
            raise ValueError("Invalid task claim credential.") from None
        obj = None
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise ValueError("Invalid task claim credential.") from None

    @classmethod
    @_finite_validation_boundary("Invalid task claim credential JSON.")
    def model_validate_json(
        cls, json_data: Any, **kwargs: Any
    ) -> "TaskClaimCredential":
        try:
            if isinstance(json_data, bytes):
                json_data = json_data.decode("utf-8", errors="strict")
            if not isinstance(json_data, str):
                raise ValueError
            payload = json.loads(json_data)
        except (UnicodeError, TypeError, ValueError):
            raise ValueError("Invalid task claim credential JSON.") from None
        json_data = None
        candidate = payload
        payload = None
        try:
            return cls.model_validate(candidate, **kwargs)
        except Exception:
            if isinstance(candidate, (dict, list)):
                candidate.clear()
            candidate = None
            raise ValueError("Invalid task claim credential JSON.") from None

    @field_validator("api_origin")
    @classmethod
    def _validate_api_origin(cls, value: str) -> str:
        return validate_fixed_api_origin(value)

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        return validate_agent_id(value)

    @field_validator("reward_address")
    @classmethod
    def _validate_reward_address(cls, value: str) -> str:
        return validate_reward_address(value)

    @field_validator("lease_expires_at")
    @classmethod
    def _validate_lease_expiry(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "lease_expires_at")

    def _claim_token_value(self) -> str:
        """Return the bearer only to the transport/private-file boundary."""

        return self._claim_token.get_secret_value()

    def _public_snapshot_tuple(self) -> tuple:
        return (
            self.api_origin,
            self.task_id,
            self.task_type,
            self.agent_id,
            self.reward_address,
            self.lease_expires_at,
            self.task_definition_version,
            self.task_definition_digest,
            self.manifest_url,
            self.manifest_sha256,
            (
                self.reward.network,
                self.reward.asset,
                self.reward.asset_address,
                self.reward.amount_atomic,
            ),
        )

    @_finite_validation_boundary("Invalid task claim credential fingerprint.")
    def _local_fingerprint(self) -> str:
        """Return a one-way, non-authoritative restart binding.

        The fingerprint is deliberately SDK-local and domain-separated.  The
        checkpoint binds the immutable public Claim fields separately; this
        value only detects whether the same bearer capability was supplied.
        It cannot be used as that capability and is never sent to Hondo.
        """

        current_public = self._public_snapshot_tuple()
        if current_public != self._bound_public_snapshot:
            raise ValueError("Invalid task claim credential fingerprint.")

        token: Optional[str] = self._claim_token_value()
        try:
            fingerprint = hashlib.sha256(
                _TASK_CREDENTIAL_FINGERPRINT_DOMAIN_SEPARATOR
                + token.encode("utf-8")
            ).hexdigest()
        finally:
            token = None
        return fingerprint

    @_finite_validation_boundary("Invalid task claim credential.")
    def _validated_snapshot(self) -> "TaskClaimCredential":
        current_public = self._public_snapshot_tuple()
        token = self._claim_token_value()
        if current_public != self._bound_public_snapshot:
            raise ValueError("Invalid task claim credential.")
        if not hmac.compare_digest(
            claim_token_storage_digest(token),
            self._claim_token_digest,
        ):
            token = None
            raise ValueError("Invalid task claim credential.")
        try:
            return type(self)(
                api_origin=current_public[0],
                task_id=current_public[1],
                task_type=current_public[2],
                agent_id=current_public[3],
                reward_address=current_public[4],
                lease_expires_at=current_public[5],
                task_definition_version=current_public[6],
                task_definition_digest=current_public[7],
                manifest_url=current_public[8],
                manifest_sha256=current_public[9],
                reward={
                    "network": current_public[10][0],
                    "asset": current_public[10][1],
                    "asset_address": current_public[10][2],
                    "amount_atomic": current_public[10][3],
                },
                claim_token=token,
            )
        finally:
            token = None

    def _to_private_file_payload(self) -> Dict[str, Any]:
        """Explicit secret-bearing payload used only by the private file codec."""

        snapshot = self._validated_snapshot()
        return {
            "schema_version": CREDENTIAL_FILE_SCHEMA_VERSION,
            "state": "ACTIVE",
            "api_origin": snapshot.api_origin,
            "task_id": snapshot.task_id,
            "task_type": snapshot.task_type,
            "task_definition_version": snapshot.task_definition_version,
            "task_definition_digest": snapshot.task_definition_digest,
            "manifest_url": snapshot.manifest_url,
            "manifest_sha256": snapshot.manifest_sha256,
            "agent_id": snapshot.agent_id,
            "reward_address": snapshot.reward_address,
            "reward": snapshot.reward.model_dump(mode="json"),
            "lease_expires_at": snapshot.lease_expires_at,
            "claim_token": snapshot._claim_token_value(),
        }

    @classmethod
    @_finite_validation_boundary("Invalid task claim credential file.")
    def _from_private_file_payload(
        cls, payload: Mapping[str, Any]
    ) -> "TaskClaimCredential":
        expected_fields = {
            "schema_version",
            "state",
            "api_origin",
            "task_id",
            "task_type",
            "task_definition_version",
            "task_definition_digest",
            "manifest_url",
            "manifest_sha256",
            "agent_id",
            "reward_address",
            "reward",
            "lease_expires_at",
            "claim_token",
        }
        try:
            if not isinstance(payload, Mapping):
                raise ValueError
            if set(payload.keys()) != expected_fields:
                raise ValueError
            if payload.get("schema_version") != CREDENTIAL_FILE_SCHEMA_VERSION:
                raise ValueError
            if payload.get("state") != "ACTIVE":
                raise ValueError
            reward = payload.get("reward")
            if (
                not isinstance(reward, Mapping)
                or set(reward.keys())
                != {"network", "asset", "asset_address", "amount_atomic"}
            ):
                raise ValueError
            return cls(
                api_origin=payload.get("api_origin"),
                task_id=payload.get("task_id"),
                task_type=payload.get("task_type"),
                task_definition_version=payload.get(
                    "task_definition_version"
                ),
                task_definition_digest=payload.get(
                    "task_definition_digest"
                ),
                manifest_url=payload.get("manifest_url"),
                manifest_sha256=payload.get("manifest_sha256"),
                agent_id=payload.get("agent_id"),
                reward_address=payload.get("reward_address"),
                reward=reward,
                lease_expires_at=payload.get("lease_expires_at"),
                claim_token=payload.get("claim_token"),
            )
        except (TypeError, ValueError, ValidationError):
            raise ValueError("Invalid task claim credential file.") from None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        snapshot = self._validated_snapshot()
        comparison_time = datetime.now(timezone.utc) if now is None else now
        if (
            not isinstance(comparison_time, datetime)
            or comparison_time.tzinfo is None
            or comparison_time.utcoffset() is None
        ):
            raise ValueError("Credential comparison time must be timezone-aware.")
        comparison_time = comparison_time.astimezone(timezone.utc)
        return parse_rfc3339_utc(
            snapshot.lease_expires_at, "lease_expires_at"
        ) <= comparison_time

    def require_active(self, now: Optional[datetime] = None) -> None:
        if self.is_expired(now=now):
            raise ValueError("Task claim credential is expired.")


class AgentTaskClaimResponse(_TaskDefinitionFieldsModel):
    """Transient wire response; its plaintext token is never serialized."""

    model_config = _FROZEN_RESPONSE_CONFIG

    schema_version: Literal["ln_church.agent_task_claim_response.v1"]
    task_id: str
    task_type: Literal["payment_surface_discovery.v1"]
    status: Literal["CLAIMED"]
    lease_duration_seconds: Literal[3600]
    lease_expires_at: str
    reward_address: str
    reward_address_control_verified: Literal[False]
    reward: AgentTaskRewardTerms
    _claim_token: SecretStr = PrivateAttr()

    @_finite_validation_boundary("Invalid task claim response.")
    def __init__(self, **data: Any) -> None:
        # This transient wire model follows the same no-retained-plaintext
        # validation boundary as TaskClaimCredential.
        raw_value = data.pop("claim_token", None)
        if isinstance(raw_value, SecretStr):
            raw_value = raw_value.get_secret_value()
        try:
            validated_token = validate_claim_token(raw_value)
        except (TypeError, ValueError):
            raw_value = None
            raise ValueError("Invalid task claim response.") from None
        secret_token = SecretStr(validated_token)
        raw_value = None
        validated_token = None
        try:
            super().__init__(**data)
        except Exception:
            data.clear()
            raise ValueError("Invalid task claim response.") from None
        self._claim_token = secret_token

    @classmethod
    @_finite_validation_boundary("Invalid task claim response.")
    def model_validate(
        cls, obj: Any, **kwargs: Any
    ) -> "AgentTaskClaimResponse":
        if isinstance(obj, cls):
            return obj
        if not isinstance(obj, Mapping):
            raise ValueError("Invalid task claim response.")
        try:
            candidate = dict(obj)
        except Exception:
            raise ValueError("Invalid task claim response.") from None
        obj = None
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise ValueError("Invalid task claim response.") from None

    @classmethod
    @_finite_validation_boundary("Invalid task claim response JSON.")
    def model_validate_json(
        cls, json_data: Any, **kwargs: Any
    ) -> "AgentTaskClaimResponse":
        try:
            if isinstance(json_data, bytes):
                json_data = json_data.decode("utf-8", errors="strict")
            if not isinstance(json_data, str):
                raise ValueError
            payload = json.loads(json_data)
        except (UnicodeError, TypeError, ValueError):
            raise ValueError("Invalid task claim response JSON.") from None
        json_data = None
        candidate = payload
        payload = None
        try:
            return cls.model_validate(candidate, **kwargs)
        except Exception:
            if isinstance(candidate, (dict, list)):
                candidate.clear()
            candidate = None
            raise ValueError("Invalid task claim response JSON.") from None

    @field_validator("lease_duration_seconds", mode="before")
    @classmethod
    def _validate_lease_duration(cls, value: Any) -> int:
        return _require_exact_int(
            value, CLAIM_LEASE_DURATION_SECONDS, "lease_duration_seconds"
        )

    @field_validator("reward_address_control_verified", mode="before")
    @classmethod
    def _validate_address_control_flag(cls, value: Any) -> bool:
        return _require_exact_bool(
            value, False, "reward_address_control_verified"
        )

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("lease_expires_at")
    @classmethod
    def _validate_lease_expiry(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "lease_expires_at")

    @field_validator("reward_address")
    @classmethod
    def _validate_reward_address(cls, value: str) -> str:
        return validate_reward_address(value)

    def _claim_token_for_conversion(self) -> str:
        return self._claim_token.get_secret_value()

    @_finite_validation_boundary("Invalid task claim response.")
    def to_claim(
        self,
        agent_id: str,
        api_origin: str = PUBLIC_API_ORIGIN,
    ) -> "AgentTaskClaim":
        credential = TaskClaimCredential(
            api_origin=api_origin,
            task_id=self.task_id,
            task_type=self.task_type,
            task_definition_version=self.task_definition_version,
            task_definition_digest=self.task_definition_digest,
            manifest_url=self.manifest_url,
            manifest_sha256=self.manifest_sha256,
            agent_id=agent_id,
            reward_address=self.reward_address,
            reward=self.reward.model_dump(mode="json"),
            lease_expires_at=self.lease_expires_at,
            claim_token=self._claim_token_for_conversion(),
        )
        return AgentTaskClaim(
            schema_version=self.schema_version,
            task_id=self.task_id,
            task_type=self.task_type,
            task_definition_version=self.task_definition_version,
            task_definition_digest=self.task_definition_digest,
            manifest_url=self.manifest_url,
            manifest_sha256=self.manifest_sha256,
            status=self.status,
            lease_duration_seconds=self.lease_duration_seconds,
            lease_expires_at=self.lease_expires_at,
            reward_address=self.reward_address,
            reward_address_control_verified=(
                self.reward_address_control_verified
            ),
            reward=self.reward.model_dump(mode="json"),
            credential=credential,
        )


class AgentTaskClaim(_TaskDefinitionFieldsModel):
    """Secret-safe successful Claim result returned by ``AgentTaskClient``."""

    model_config = _FROZEN_RESPONSE_CONFIG

    schema_version: Literal["ln_church.agent_task_claim_response.v1"]
    task_id: str
    task_type: Literal["payment_surface_discovery.v1"]
    status: Literal["CLAIMED"]
    lease_duration_seconds: Literal[3600]
    lease_expires_at: str
    reward_address: str
    reward_address_control_verified: Literal[False]
    reward: AgentTaskRewardTerms
    credential: TaskClaimCredential

    @field_validator("lease_duration_seconds", mode="before")
    @classmethod
    def _validate_lease_duration(cls, value: Any) -> int:
        return _require_exact_int(
            value, CLAIM_LEASE_DURATION_SECONDS, "lease_duration_seconds"
        )

    @field_validator("reward_address_control_verified", mode="before")
    @classmethod
    def _validate_address_control_flag(cls, value: Any) -> bool:
        return _require_exact_bool(
            value, False, "reward_address_control_verified"
        )

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("lease_expires_at")
    @classmethod
    def _validate_lease_expiry(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "lease_expires_at")

    @field_validator("reward_address")
    @classmethod
    def _validate_reward_address(cls, value: str) -> str:
        return validate_reward_address(value)

    @model_validator(mode="after")
    def _validate_credential_binding(self) -> "AgentTaskClaim":
        credential = self.credential
        if (
            credential.task_id != self.task_id
            or credential.task_type != self.task_type
            or credential.task_definition != self.task_definition
            or credential.reward_address != self.reward_address
            or credential.reward != self.reward
            or credential.lease_expires_at != self.lease_expires_at
        ):
            raise ValueError("Task claim credential binding mismatch.")
        return self


class TaskObservedUrlEntry(_StrictRequestModel):
    url: str
    method: TaskMethodValue
    status_code: int = Field(ge=100, le=599)
    media_family: MediaFamilyValue
    observed_at: str

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return validate_public_observation_url(value)

    @field_validator("observed_at")
    @classmethod
    def _validate_observed_at(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "observed_at")


class TaskDiscoveredSurfaceEntry(_StrictRequestModel):
    url: str
    method: TaskMethodValue
    status_code: int = Field(ge=100, le=599)
    surface_type: SurfaceTypeValue
    observed_at: str

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return validate_public_observation_url(value)

    @field_validator("observed_at")
    @classmethod
    def _validate_observed_at(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "observed_at")


class TaskObservationErrorEntry(_StrictRequestModel):
    url: str
    stage: ObservationStageValue
    error_code: ObservationErrorCodeValue
    observed_at: str

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return validate_public_observation_url(value)

    @field_validator("observed_at")
    @classmethod
    def _validate_observed_at(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "observed_at")


class TaskVerificationCostVector(_StrictRequestModel):
    http_requests: int = Field(default=0, ge=0, le=100)
    tool_calls: int = Field(default=0, ge=0, le=100)
    payment_attempts: Literal[0] = 0
    personal_data_required: Literal[False] = False
    human_confirmation_required: bool = False
    irreversible_action_attempted: Literal[False] = False
    login_attempted: Literal[False] = False
    form_submission_attempted: Literal[False] = False
    vulnerability_scan_attempted: Literal[False] = False

    @field_validator("http_requests", "tool_calls", mode="before")
    @classmethod
    def _validate_bounded_integer_type(cls, value: Any) -> int:
        if type(value) is not int:
            raise ValueError("Verification cost counters must be integers.")
        return value

    @field_validator("payment_attempts", mode="before")
    @classmethod
    def _validate_zero_payment_attempts(cls, value: Any) -> int:
        return _require_exact_int(value, 0, "payment_attempts")

    @field_validator(
        "personal_data_required",
        "irreversible_action_attempted",
        "login_attempted",
        "form_submission_attempted",
        "vulnerability_scan_attempted",
        mode="before",
    )
    @classmethod
    def _validate_fixed_false(cls, value: Any) -> bool:
        return _require_exact_bool(value, False, "public-safe cost flag")

    @field_validator("human_confirmation_required", mode="before")
    @classmethod
    def _validate_boolean_cost(cls, value: Any) -> bool:
        if type(value) is not bool:
            raise ValueError("Invalid human_confirmation_required.")
        return value


class TaskDomainObservationSubmission(_StrictRequestModel):
    schema_version: Literal[
        "ln_church.task_domain_observation_submission.v1"
    ] = OBSERVATION_SUBMISSION_SCHEMA_VERSION
    submission_id: str = Field(default_factory=generate_submission_id)
    observed_domain: str
    observed_urls: List[TaskObservedUrlEntry] = Field(
        default_factory=list, max_length=MAXIMUM_OBSERVED_URLS
    )
    discovered_surfaces: List[TaskDiscoveredSurfaceEntry] = Field(
        default_factory=list, max_length=MAXIMUM_DISCOVERED_SURFACES
    )
    errors: List[TaskObservationErrorEntry] = Field(
        default_factory=list, max_length=MAXIMUM_OBSERVATION_ERRORS
    )
    safety_profile: Literal["public_safe_light"] = "public_safe_light"
    no_payment_to_target: Literal[True] = True
    not_a_security_scan: Literal[True] = True
    verification_cost_vector: TaskVerificationCostVector = Field(
        default_factory=TaskVerificationCostVector
    )

    @field_validator(
        "no_payment_to_target", "not_a_security_scan", mode="before"
    )
    @classmethod
    def _validate_fixed_true(cls, value: Any) -> bool:
        return _require_exact_bool(value, True, "public-safe submission flag")

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("observed_domain")
    @classmethod
    def _validate_observed_domain(cls, value: str) -> str:
        return validate_public_domain(value, "observed_domain")

    @model_validator(mode="after")
    def _validate_domain_scope(self) -> "TaskDomainObservationSubmission":
        for entry in self.observed_urls:
            validate_public_observation_url(
                entry.url,
                task_domain=self.observed_domain,
                field_name="observed URL",
            )
        for entry in self.discovered_surfaces:
            validate_public_observation_url(
                entry.url,
                task_domain=self.observed_domain,
                field_name="discovered surface URL",
            )
        for entry in self.errors:
            validate_public_observation_url(
                entry.url,
                task_domain=self.observed_domain,
                field_name="error URL",
            )
        if not any(
            entry.status_code == 402 for entry in self.discovered_surfaces
        ):
            raise ValueError(
                "Task submission requires an actual HTTP 402 surface."
            )
        return self

    @classmethod
    def _validated_snapshot(
        cls,
        value: Any,
    ) -> "TaskDomainObservationSubmission":
        if not isinstance(value, (BaseModel, Mapping)):
            raise ValueError("Invalid Task domain observation submission.")
        snapshot: Any = None
        try:
            snapshot = _strict_snapshot_value(value)
            return cls.model_validate(snapshot, strict=True)
        except Exception:
            snapshot = None
            raise ValueError(
                "Invalid Task domain observation submission."
            ) from None

    @_finite_validation_boundary(
        "Invalid Task domain observation submission."
    )
    def canonical_bytes(self) -> bytes:
        validated = self._validated_snapshot(self)
        return canonical_submission_bytes(
            validated.model_dump(mode="json")
        )

    @_finite_validation_boundary(
        "Invalid Task domain observation submission."
    )
    def canonical_digest(self) -> bytes:
        validated = self._validated_snapshot(self)
        return canonical_submission_digest(
            validated.model_dump(mode="json")
        )

    @_finite_validation_boundary(
        "Invalid Task domain observation submission."
    )
    def canonical_digest_hex(self) -> str:
        validated = self._validated_snapshot(self)
        return canonical_submission_digest_hex(
            validated.model_dump(mode="json")
        )

    @property
    def idempotency_digest(self) -> str:
        return self.canonical_digest_hex()


class TaskDomainObservationResponse(_StrictResponseModel):
    schema_version: Literal[
        "ln_church.task_domain_observation_response.v1"
    ]
    accepted: Literal[True]
    task_id: str
    submission_id: str
    observation_id: str
    status: Literal["recorded"]

    @field_validator("accepted", mode="before")
    @classmethod
    def _validate_accepted(cls, value: Any) -> bool:
        return _require_exact_bool(value, True, "accepted")

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("observation_id")
    @classmethod
    def _validate_observation_id(cls, value: str) -> str:
        return validate_observation_id(value)


class AgentTaskCompletionRequest(_StrictRequestModel):
    schema_version: Literal[
        "ln_church.agent_task_completion_request.v1"
    ] = COMPLETION_REQUEST_SCHEMA_VERSION
    submission_id: str
    observation_id: str

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("observation_id")
    @classmethod
    def _validate_observation_id(cls, value: str) -> str:
        return validate_observation_id(value)


class AgentTaskCompletionResponse(_StrictResponseModel):
    schema_version: Literal[
        "ln_church.agent_task_completion_response.v1"
    ]
    accepted: Literal[True]
    task_id: str
    submission_id: str
    observation_id: str
    status: Literal["SUBMITTED"]

    @field_validator("accepted", mode="before")
    @classmethod
    def _validate_accepted(cls, value: Any) -> bool:
        return _require_exact_bool(value, True, "accepted")

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("observation_id")
    @classmethod
    def _validate_observation_id(cls, value: str) -> str:
        return validate_observation_id(value)


class AgentTaskRewardStatus(_TaskDefinitionFieldsModel):
    schema_version: Literal[
        "ln_church.agent_task_reward_status.v1"
    ]
    task_id: str
    submission_id: str
    observation_id: str
    task_status: ExecutionTaskStatusValue
    reward_state: RewardStateValue
    network: Literal["eip155:8453"]
    asset: Literal["USDC"]
    asset_address: Literal[
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    ]
    amount_atomic: str
    reward_tx_hash: Optional[str]
    rewarded_at: Optional[str]
    failure_code: Optional[PublicTaskFailureCodeValue]

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("observation_id")
    @classmethod
    def _validate_observation_id(cls, value: str) -> str:
        return validate_observation_id(value)

    @field_validator("amount_atomic")
    @classmethod
    def _validate_amount_atomic(cls, value: str) -> str:
        return validate_amount_atomic(value)

    @field_validator("reward_tx_hash")
    @classmethod
    def _validate_optional_transaction_hash(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        return validate_transaction_hash(value)

    @field_validator("rewarded_at")
    @classmethod
    def _validate_optional_rewarded_at(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        return validate_rfc3339_utc(value, "rewarded_at")

    @model_validator(mode="after")
    def _validate_reward_invariants(self) -> "AgentTaskRewardStatus":
        _validate_public_submission_projection(
            task_status=self.task_status,
            reward_state=self.reward_state,
            reward_tx_hash=self.reward_tx_hash,
            rewarded_at=self.rewarded_at,
            failure_code=self.failure_code,
            require_evaluated_at_field=False,
        )
        return self


@_finite_validation_boundary("Invalid Task Execution summary binding.")
def verify_task_execution_summary(
    credential: TaskClaimCredential,
    task: AgentTask,
    summary: AgentTaskExecutionSummary,
    *,
    submission_id: str,
    observation_id: str,
) -> AgentTaskExecutionSummary:
    """Verify one Task-detail summary against a known Claim snapshot.

    This operation is entirely local.  The Task-detail advertised reward is
    deliberately not consulted: reward authority for this Execution is the
    immutable successful-Claim snapshot held by ``credential``.
    """

    if type(credential) is not TaskClaimCredential:
        raise ValueError("Invalid Task Execution summary binding.")
    if type(task) is not AgentTask:
        raise ValueError("Invalid Task Execution summary binding.")
    if type(summary) is not AgentTaskExecutionSummary:
        raise ValueError("Invalid Task Execution summary binding.")

    credential_snapshot = credential._validated_snapshot()
    task_snapshot = _exact_model_snapshot(
        task,
        AgentTask,
        "Invalid Task detail.",
    )
    summary_snapshot = _exact_model_snapshot(
        summary,
        AgentTaskExecutionSummary,
        "Invalid Task Execution summary.",
    )
    expected_submission_id = validate_submission_id(submission_id)
    expected_observation_id = validate_observation_id(observation_id)

    if (
        task_snapshot.task_id != credential_snapshot.task_id
        or task_snapshot.task_type != credential_snapshot.task_type
        or task_snapshot.task_definition
        != credential_snapshot.task_definition
        or summary_snapshot.submission_id != expected_submission_id
        or summary_snapshot.observation_id != expected_observation_id
        or summary_snapshot not in task_snapshot.execution_summaries
        or summary_snapshot.network
        != credential_snapshot.reward.network
        or summary_snapshot.asset != credential_snapshot.reward.asset
        or summary_snapshot.asset_address
        != credential_snapshot.reward.asset_address
        or summary_snapshot.amount_atomic
        != credential_snapshot.reward.amount_atomic
    ):
        raise ValueError("Invalid Task Execution summary binding.")
    return summary_snapshot


@_finite_validation_boundary("Invalid Task reward status transition.")
def verify_reward_status_transition(
    previous: AgentTaskRewardStatus,
    current: AgentTaskRewardStatus,
) -> AgentTaskRewardStatus:
    """Verify the one explicit AMBIGUOUS-to-REWARDED refresh transition."""

    if (
        type(previous) is not AgentTaskRewardStatus
        or type(current) is not AgentTaskRewardStatus
    ):
        raise ValueError("Invalid Task reward status transition.")
    previous_snapshot = _exact_model_snapshot(
        previous,
        AgentTaskRewardStatus,
        "Invalid prior Task reward status.",
    )
    current_snapshot = _exact_model_snapshot(
        current,
        AgentTaskRewardStatus,
        "Invalid current Task reward status.",
    )
    if (
        previous_snapshot.task_status != "REWARD_AMBIGUOUS"
        or current_snapshot.task_status != "REWARDED"
        or previous_snapshot.task_id != current_snapshot.task_id
        or previous_snapshot.submission_id != current_snapshot.submission_id
        or previous_snapshot.observation_id != current_snapshot.observation_id
        or previous_snapshot.task_definition
        != current_snapshot.task_definition
        or previous_snapshot.network != current_snapshot.network
        or previous_snapshot.asset != current_snapshot.asset
        or previous_snapshot.asset_address != current_snapshot.asset_address
        or previous_snapshot.amount_atomic != current_snapshot.amount_atomic
        or (
            previous_snapshot.reward_tx_hash is not None
            and previous_snapshot.reward_tx_hash
            != current_snapshot.reward_tx_hash
        )
    ):
        raise ValueError("Invalid Task reward status transition.")
    return current_snapshot


class TaskDomainObservationCheckpoint(_TaskDefinitionFieldsModel):
    """Secret-free SDK-local restart metadata for the guided Task bridge.

    This model is neither Hondo state nor an execution, evaluation, settlement,
    or reward authority.  Its credential fingerprint is only a one-way local
    equality binding; it is not a bearer credential.
    """

    model_config = _FROZEN_REQUEST_CONFIG

    schema_version: Literal[
        "ln_church.task_domain_observation_checkpoint.v1"
    ] = _TASK_DOMAIN_OBSERVATION_CHECKPOINT_SCHEMA_VERSION
    state: TaskDomainObservationCheckpointStateValue
    api_origin: Literal["https://kari.mayim-mayim.com"] = PUBLIC_API_ORIGIN
    task_id: str
    task_type: Literal["payment_surface_discovery.v1"]
    agent_id: str
    reward_address: str
    reward: AgentTaskRewardTerms
    lease_expires_at: str
    submission: TaskDomainObservationSubmission
    submission_id: str
    submission_sha256: str
    credential_fingerprint: str
    register_receipt: Optional[TaskDomainObservationResponse] = None
    observation_id: Optional[str] = None
    _bound_values: tuple = PrivateAttr()
    _sealed: bool = PrivateAttr(default=False)

    @_finite_validation_boundary(
        "Invalid Task domain observation checkpoint."
    )
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._bound_values = self._current_bound_values()
        self._sealed = True

    @_finite_validation_boundary(
        "Task domain observation checkpoint is immutable."
    )
    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise ValueError(
                "Task domain observation checkpoint is immutable."
            )
        super().__setattr__(name, value)

    def __getattribute__(self, name: str) -> Any:
        value = super().__getattribute__(name)
        if name in {"submission", "reward", "register_receipt"}:
            integrity_failed = False
            try:
                try:
                    private_values = super().__getattribute__(
                        "__pydantic_private__"
                    )
                    sealed = bool(
                        private_values
                        and private_values.get("_sealed", False)
                    )
                except (AttributeError, TypeError):
                    sealed = False
                if sealed:
                    super().__getattribute__("_require_intact")()
            except Exception:
                integrity_failed = True
            if integrity_failed:
                value = None
                raise ValueError(
                    "Invalid Task domain observation checkpoint."
                )
        if (
            name == "submission"
            and type(value) is TaskDomainObservationSubmission
        ):
            try:
                return TaskDomainObservationSubmission._validated_snapshot(
                    value
                )
            except Exception:
                pass
            value = None
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            )
        if name == "reward" and type(value) is AgentTaskRewardTerms:
            try:
                return _exact_model_snapshot(
                    value,
                    AgentTaskRewardTerms,
                    "Invalid Task domain observation checkpoint.",
                )
            except Exception:
                pass
            value = None
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            )
        if (
            name == "register_receipt"
            and type(value) is TaskDomainObservationResponse
        ):
            try:
                return TaskDomainObservationResponse.model_validate(
                    _strict_snapshot_value(value),
                    strict=True,
                )
            except Exception:
                pass
            value = None
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            )
        return value

    @classmethod
    @_finite_validation_boundary(
        "Invalid Task domain observation checkpoint."
    )
    def model_validate(
        cls, obj: Any, **kwargs: Any
    ) -> "TaskDomainObservationCheckpoint":
        if isinstance(obj, cls):
            return obj._validated_snapshot()
        if not isinstance(obj, Mapping):
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            )
        try:
            candidate = dict(obj)
        except Exception:
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            ) from None
        obj = None
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            ) from None

    @classmethod
    @_finite_validation_boundary(
        "Invalid Task domain observation checkpoint JSON."
    )
    def model_validate_json(
        cls, json_data: Any, **kwargs: Any
    ) -> "TaskDomainObservationCheckpoint":
        try:
            if isinstance(json_data, bytes):
                json_data = json_data.decode("utf-8", errors="strict")
            if not isinstance(json_data, str):
                raise ValueError
            payload = json.loads(json_data)
        except (UnicodeError, TypeError, ValueError):
            raise ValueError(
                "Invalid Task domain observation checkpoint JSON."
            ) from None
        json_data = None
        candidate = payload
        payload = None
        try:
            return cls.model_validate(candidate, **kwargs)
        except Exception:
            if isinstance(candidate, (dict, list)):
                candidate.clear()
            candidate = None
            raise ValueError(
                "Invalid Task domain observation checkpoint JSON."
            ) from None

    @field_validator("api_origin")
    @classmethod
    def _validate_api_origin(cls, value: str) -> str:
        return validate_fixed_api_origin(value)

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        return validate_agent_id(value)

    @field_validator("reward_address")
    @classmethod
    def _validate_reward_address(cls, value: str) -> str:
        return validate_reward_address(value)

    @field_validator("lease_expires_at")
    @classmethod
    def _validate_lease_expiry(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "lease_expires_at")

    @field_validator("submission", mode="before")
    @classmethod
    def _snapshot_submission(
        cls, value: Any
    ) -> TaskDomainObservationSubmission:
        return TaskDomainObservationSubmission._validated_snapshot(value)

    @field_validator("reward", mode="before")
    @classmethod
    def _snapshot_checkpoint_reward(
        cls, value: Any
    ) -> AgentTaskRewardTerms:
        return _exact_model_snapshot(
            value,
            AgentTaskRewardTerms,
            "Invalid Task checkpoint reward.",
        )

    @field_validator("submission_id")
    @classmethod
    def _validate_submission_id(cls, value: str) -> str:
        return validate_submission_id(value)

    @field_validator("submission_sha256", "credential_fingerprint")
    @classmethod
    def _validate_local_sha256(cls, value: str) -> str:
        value = validate_nfc_string(
            value,
            "local SHA-256 digest",
            minimum_utf8_bytes=64,
            maximum_utf8_bytes=64,
        )
        try:
            decoded = bytes.fromhex(value)
        except (TypeError, ValueError):
            raise ValueError("Invalid local SHA-256 digest.") from None
        if len(decoded) != 32 or value != value.lower():
            raise ValueError("Invalid local SHA-256 digest.")
        return value

    @field_validator("register_receipt", mode="before")
    @classmethod
    def _snapshot_register_receipt(
        cls, value: Any
    ) -> Optional[TaskDomainObservationResponse]:
        if value is None:
            return None
        return _exact_model_snapshot(
            value,
            TaskDomainObservationResponse,
            "Invalid Task domain observation Register receipt.",
        )

    @field_validator("observation_id")
    @classmethod
    def _validate_optional_observation_id(
        cls, value: Optional[str]
    ) -> Optional[str]:
        if value is None:
            return None
        return validate_observation_id(value)

    @model_validator(mode="after")
    def _validate_checkpoint_bindings(
        self,
    ) -> "TaskDomainObservationCheckpoint":
        if self.submission.submission_id != self.submission_id:
            raise ValueError("Task checkpoint submission binding mismatch.")
        if not hmac.compare_digest(
            self.submission.canonical_digest_hex(),
            self.submission_sha256,
        ):
            raise ValueError("Task checkpoint submission digest mismatch.")

        receipt = self.register_receipt
        if self.state == "REGISTER_PENDING":
            if receipt is not None or self.observation_id is not None:
                raise ValueError(
                    "REGISTER_PENDING checkpoint has a Register receipt."
                )
            return self

        if (
            self.state != "REGISTERED"
            or receipt is None
            or self.observation_id is None
        ):
            raise ValueError(
                "REGISTERED checkpoint requires a Register receipt."
            )
        if (
            receipt.task_id != self.task_id
            or receipt.submission_id != self.submission_id
            or receipt.observation_id != self.observation_id
        ):
            raise ValueError("Task checkpoint Register binding mismatch.")
        return self

    def _current_bound_values(self) -> tuple:
        receipt = super().__getattribute__("register_receipt")
        submission = super().__getattribute__("submission")
        reward = super().__getattribute__("reward")
        receipt_values = (
            None
            if receipt is None
            else (
                receipt.schema_version,
                receipt.accepted,
                receipt.task_id,
                receipt.submission_id,
                receipt.observation_id,
                receipt.status,
            )
        )
        return (
            self.schema_version,
            self.state,
            self.api_origin,
            self.task_id,
            self.task_type,
            self.task_definition_version,
            self.task_definition_digest,
            self.manifest_url,
            self.manifest_sha256,
            self.agent_id,
            self.reward_address,
            (
                reward.network,
                reward.asset,
                reward.asset_address,
                reward.amount_atomic,
            ),
            self.lease_expires_at,
            submission.canonical_bytes(),
            self.submission_id,
            self.submission_sha256,
            self.credential_fingerprint,
            receipt_values,
            self.observation_id,
        )

    def _require_intact(self) -> None:
        try:
            current = self._current_bound_values()
        except Exception:
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            ) from None
        if current != self._bound_values:
            raise ValueError(
                "Invalid Task domain observation checkpoint."
            )

    @_finite_validation_boundary(
        "Invalid Task domain observation checkpoint."
    )
    def _validated_snapshot(self) -> "TaskDomainObservationCheckpoint":
        self._require_intact()
        payload = BaseModel.model_dump(
            self,
            mode="python",
            exclude_none=False,
        )
        return type(self).model_validate(payload, strict=True)

    def model_dump(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        self._require_intact()
        return super().model_dump(*args, **kwargs)

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        self._require_intact()
        return super().model_dump_json(*args, **kwargs)

    def __repr__(self) -> str:
        try:
            self._require_intact()
        except Exception:
            return "TaskDomainObservationCheckpoint(<invalid>)"
        return super().__repr__()

    def __str__(self) -> str:
        try:
            self._require_intact()
        except Exception:
            return "TaskDomainObservationCheckpoint(<invalid>)"
        return super().__str__()


class TaskDomainObservationGuidedResult(_StrictRequestModel):
    """Exact receipts returned by one bounded guided Register/Completion run.

    A direct Completion 2xx carries its exact receipt.  If that exchange was
    ambiguous, the result instead carries the exact matching status used for
    reconciliation.  A synthetic Completion receipt is never represented as
    an exact server receipt.
    """

    model_config = _FROZEN_REQUEST_CONFIG

    schema_version: Literal[
        "ln_church.task_domain_observation_guided_result.v1"
    ] = _TASK_DOMAIN_OBSERVATION_GUIDED_RESULT_SCHEMA_VERSION
    register_receipt: TaskDomainObservationResponse
    completion_receipt: Optional[AgentTaskCompletionResponse] = None
    matched_status: Optional[AgentTaskRewardStatus] = None
    _bound_values: tuple = PrivateAttr()
    _sealed: bool = PrivateAttr(default=False)

    @_finite_validation_boundary(
        "Invalid Task domain observation guided result."
    )
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._bound_values = self._current_bound_values()
        self._sealed = True

    @_finite_validation_boundary(
        "Task domain observation guided result is immutable."
    )
    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise ValueError(
                "Task domain observation guided result is immutable."
            )
        super().__setattr__(name, value)

    def __getattribute__(self, name: str) -> Any:
        value = super().__getattribute__(name)
        model_type: Any = None
        if name == "register_receipt":
            model_type = TaskDomainObservationResponse
        elif name == "completion_receipt":
            model_type = AgentTaskCompletionResponse
        elif name == "matched_status":
            model_type = AgentTaskRewardStatus
        if model_type is not None and type(value) is model_type:
            integrity_failed = False
            try:
                try:
                    private_values = super().__getattribute__(
                        "__pydantic_private__"
                    )
                    sealed = bool(
                        private_values
                        and private_values.get("_sealed", False)
                    )
                except (AttributeError, TypeError):
                    sealed = False
                if sealed:
                    super().__getattribute__("_require_intact")()
            except Exception:
                integrity_failed = True
            if integrity_failed:
                value = None
                model_type = None
                raise ValueError(
                    "Invalid Task domain observation guided result."
                )
            try:
                return model_type.model_validate(
                    _strict_snapshot_value(value),
                    strict=True,
                )
            except Exception:
                pass
            value = None
            model_type = None
            raise ValueError(
                "Invalid Task domain observation guided result."
            )
        return value

    @classmethod
    @_finite_validation_boundary(
        "Invalid Task domain observation guided result."
    )
    def model_validate(
        cls, obj: Any, **kwargs: Any
    ) -> "TaskDomainObservationGuidedResult":
        if isinstance(obj, cls):
            return obj._validated_snapshot()
        if not isinstance(obj, Mapping):
            raise ValueError(
                "Invalid Task domain observation guided result."
            )
        try:
            candidate = dict(obj)
        except Exception:
            raise ValueError(
                "Invalid Task domain observation guided result."
            ) from None
        obj = None
        try:
            return cls(**candidate)
        except Exception:
            candidate.clear()
            raise ValueError(
                "Invalid Task domain observation guided result."
            ) from None

    @classmethod
    @_finite_validation_boundary(
        "Invalid Task domain observation guided result JSON."
    )
    def model_validate_json(
        cls, json_data: Any, **kwargs: Any
    ) -> "TaskDomainObservationGuidedResult":
        try:
            if isinstance(json_data, bytes):
                json_data = json_data.decode("utf-8", errors="strict")
            if not isinstance(json_data, str):
                raise ValueError
            payload = json.loads(json_data)
        except (UnicodeError, TypeError, ValueError):
            raise ValueError(
                "Invalid Task domain observation guided result JSON."
            ) from None
        json_data = None
        candidate = payload
        payload = None
        try:
            return cls.model_validate(candidate, **kwargs)
        except Exception:
            if isinstance(candidate, (dict, list)):
                candidate.clear()
            candidate = None
            raise ValueError(
                "Invalid Task domain observation guided result JSON."
            ) from None

    @field_validator("register_receipt", mode="before")
    @classmethod
    def _snapshot_result_register_receipt(
        cls, value: Any
    ) -> TaskDomainObservationResponse:
        return _exact_model_snapshot(
            value,
            TaskDomainObservationResponse,
            "Invalid guided Task Register receipt.",
        )

    @field_validator("completion_receipt", mode="before")
    @classmethod
    def _snapshot_completion_receipt(
        cls, value: Any
    ) -> Optional[AgentTaskCompletionResponse]:
        if value is None:
            return None
        return _exact_model_snapshot(
            value,
            AgentTaskCompletionResponse,
            "Invalid guided Task Completion receipt.",
        )

    @field_validator("matched_status", mode="before")
    @classmethod
    def _snapshot_matched_status(
        cls, value: Any
    ) -> Optional[AgentTaskRewardStatus]:
        if value is None:
            return None
        return _exact_model_snapshot(
            value,
            AgentTaskRewardStatus,
            "Invalid guided Task matched status.",
        )

    @model_validator(mode="after")
    def _validate_result_bindings(
        self,
    ) -> "TaskDomainObservationGuidedResult":
        register = self.register_receipt
        completion = self.completion_receipt
        status = self.matched_status
        if (completion is None) == (status is None):
            raise ValueError(
                "Guided Task result requires exactly one Completion proof."
            )

        proof = completion if completion is not None else status
        if (
            proof is None
            or proof.task_id != register.task_id
            or proof.submission_id != register.submission_id
            or proof.observation_id != register.observation_id
        ):
            raise ValueError("Guided Task result receipt binding mismatch.")
        if status is not None and status.task_status not in {
            "SUBMITTED",
            "EVALUATION_REJECTED",
            "REWARD_PENDING",
            "REWARDED",
            "REWARD_FAILED",
            "REWARD_AMBIGUOUS",
        }:
            raise ValueError(
                "Guided Task matched status does not reconcile Completion."
            )
        return self

    def _current_bound_values(self) -> tuple:
        register = super().__getattribute__("register_receipt")
        completion = super().__getattribute__("completion_receipt")
        status = super().__getattribute__("matched_status")
        completion_values = (
            None
            if completion is None
            else (
                completion.schema_version,
                completion.accepted,
                completion.task_id,
                completion.submission_id,
                completion.observation_id,
                completion.status,
            )
        )
        status_values = (
            None
            if status is None
            else (
                status.schema_version,
                status.task_id,
                status.submission_id,
                status.observation_id,
                status.task_definition_version,
                status.task_definition_digest,
                status.manifest_url,
                status.manifest_sha256,
                status.task_status,
                status.reward_state,
                status.network,
                status.asset,
                status.asset_address,
                status.amount_atomic,
                status.reward_tx_hash,
                status.rewarded_at,
                status.failure_code,
            )
        )
        return (
            self.schema_version,
            (
                register.schema_version,
                register.accepted,
                register.task_id,
                register.submission_id,
                register.observation_id,
                register.status,
            ),
            completion_values,
            status_values,
        )

    def _require_intact(self) -> None:
        try:
            current = self._current_bound_values()
        except Exception:
            raise ValueError(
                "Invalid Task domain observation guided result."
            ) from None
        if current != self._bound_values:
            raise ValueError(
                "Invalid Task domain observation guided result."
            )

    @_finite_validation_boundary(
        "Invalid Task domain observation guided result."
    )
    def _validated_snapshot(self) -> "TaskDomainObservationGuidedResult":
        self._require_intact()
        payload = BaseModel.model_dump(
            self,
            mode="python",
            exclude_none=False,
        )
        return type(self).model_validate(payload, strict=True)

    def model_dump(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        self._require_intact()
        return super().model_dump(*args, **kwargs)

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        self._require_intact()
        return super().model_dump_json(*args, **kwargs)

    def __repr__(self) -> str:
        try:
            self._require_intact()
        except Exception:
            return "TaskDomainObservationGuidedResult(<invalid>)"
        return super().__repr__()

    def __str__(self) -> str:
        try:
            self._require_intact()
        except Exception:
            return "TaskDomainObservationGuidedResult(<invalid>)"
        return super().__str__()


class AgentTaskErrorResponse(_StrictResponseModel):
    schema_version: Literal["ln_church.agent_task_error.v1"]
    error_code: PublicTaskErrorCodeValue


class TaskClaimOutcomeUnknownTombstone(_StrictRequestModel):
    schema_version: Literal[
        "ln_church.task_claim_credential_file.v1"
    ] = CREDENTIAL_FILE_SCHEMA_VERSION
    state: Literal["CLAIM_OUTCOME_UNKNOWN"] = "CLAIM_OUTCOME_UNKNOWN"
    api_origin: Literal["https://kari.mayim-mayim.com"] = PUBLIC_API_ORIGIN
    task_id: str
    created_at: str

    @field_validator("api_origin")
    @classmethod
    def _validate_api_origin(cls, value: str) -> str:
        return validate_fixed_api_origin(value)

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return validate_task_id(value)

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: str) -> str:
        return validate_rfc3339_utc(value, "created_at")


# Short, discoverable aliases for the exact nested wire entries.
ObservedUrlEntry = TaskObservedUrlEntry
DiscoveredSurfaceEntry = TaskDiscoveredSurfaceEntry
ObservationErrorEntry = TaskObservationErrorEntry
VerificationCostVector = TaskVerificationCostVector
TaskDomainObservationRequest = TaskDomainObservationSubmission
TaskCompletionRequest = AgentTaskCompletionRequest


__all__ = [
    "AgentTask",
    "AgentTaskClaim",
    "AgentTaskClaimRequest",
    "AgentTaskClaimResponse",
    "AgentTaskCompletionRequest",
    "AgentTaskCompletionResponse",
    "AgentTaskConstraints",
    "AgentTaskDetail",
    "AgentTaskDetailQuery",
    "AgentTaskErrorResponse",
    "AgentTaskExecutionSummary",
    "AgentTaskListQuery",
    "AgentTaskListItem",
    "AgentTaskPage",
    "AgentTaskPocTerms",
    "AgentTaskClaimStatus",
    "AgentTaskRewardState",
    "AgentTaskRewardStatus",
    "AgentTaskRewardTerms",
    "AgentTaskStatus",
    "AgentTaskSubmissionStatus",
    "DiscoveredSurfaceEntry",
    "ObservationErrorEntry",
    "ObservedUrlEntry",
    "TaskClaimCredential",
    "TaskClaimOutcomeUnknownTombstone",
    "TaskCompletionRequest",
    "TaskDiscoveredSurfaceEntry",
    "TaskDomainObservationRequest",
    "TaskDomainObservationCheckpoint",
    "TaskDomainObservationCheckpointState",
    "TaskDomainObservationGuidedResult",
    "TaskDomainObservationResponse",
    "TaskDomainObservationSubmission",
    "TaskDefinitionReference",
    "TaskObservationErrorEntry",
    "TaskObservedUrlEntry",
    "TaskVerificationCostVector",
    "VerificationCostVector",
    "verify_reward_status_transition",
    "verify_task_execution_summary",
]
