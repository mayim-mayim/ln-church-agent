"""Wallet-keyless public Agent Task lifecycle client.

``AgentTaskClient`` is deliberately separate from the payment-capable
``LnChurchClient``.  It has no wallet, signer, payment, redirect, telemetry, or
internal-secret behavior.
"""

from __future__ import annotations

import copy
from functools import wraps
import math
import random
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from pydantic import ValidationError

from .task_contract import (
    PUBLIC_API_ORIGIN,
    TASK_LIST_PATH,
    TASK_TYPE_PAYMENT_SURFACE_DISCOVERY,
    task_claim_path,
    task_completion_path,
    task_detail_path,
    task_observation_path,
    task_submission_status_path,
    validate_fixed_api_origin,
    validate_observation_id,
    validate_submission_id,
    validate_task_id,
)
from .task_models import (
    AgentTask,
    AgentTaskClaim,
    AgentTaskClaimRequest,
    AgentTaskClaimResponse,
    AgentTaskCompletionRequest,
    AgentTaskCompletionResponse,
    AgentTaskDetailQuery,
    AgentTaskListQuery,
    AgentTaskPage,
    AgentTaskRewardTerms,
    AgentTaskRewardStatus,
    TaskDefinitionReference,
    TaskClaimCredential,
    TaskDomainObservationCheckpoint,
    TaskDomainObservationCheckpointState,
    TaskDomainObservationGuidedResult,
    TaskDomainObservationResponse,
    TaskDomainObservationSubmission,
)
from .task_transport import (
    TaskAPIError,
    TaskAmbiguousOutcomeError,
    TaskError,
    TaskTransport,
    TaskTransportError,
    TaskTransportResponse,
    _TaskExchangeBudget,
    _detached_task_error,
)


def _public_client_error_boundary(
    function: Callable[..., Any],
) -> Callable[..., Any]:
    """Return only a fresh finite Task error from a public client call."""

    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        clean_error: Optional[TaskError] = None
        try:
            return function(*args, **kwargs)
        except TaskError as error:
            clean_error = _detached_task_error(error)
        except Exception:
            clean_error = TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=None
            )
        args = ()
        kwargs.clear()
        raise clean_error

    return wrapped


def _response_payload(response: Any) -> Dict[str, Any]:
    try:
        payload = response.data
    except Exception:
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=True
        ) from None
    if type(payload) is not dict:
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=True
        )
    return dict(payload)


def _claim_response_payload(response: Any) -> Dict[str, Any]:
    accessor = getattr(response, "_claim_data_for_model", None)
    if callable(accessor):
        try:
            payload = accessor()
        except Exception:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            ) from None
    else:
        payload = _response_payload(response)
    if type(payload) is not dict:
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=True
        )
    return dict(payload)


def _response_model(model_type: Any, payload: Mapping[str, Any]) -> Any:
    try:
        if type(payload) is not dict:
            raise ValueError
        # Response models ignore additions and reconstruct only their fixed
        # public allowlist.
        return model_type.model_validate(dict(payload))
    except (TypeError, ValueError, ValidationError):
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=True
        ) from None


def _local_invalid(code: str = "TASK_RESPONSE_INVALID") -> TaskTransportError:
    return TaskTransportError(code, request_bytes_sent=False)


def _credential_is_active(credential: Any) -> TaskClaimCredential:
    if type(credential) is not TaskClaimCredential:
        raise _local_invalid("TASK_CREDENTIAL_INVALID")
    try:
        snapshot = credential._validated_snapshot()
        if snapshot.api_origin != PUBLIC_API_ORIGIN:
            raise ValueError
        expired = snapshot.is_expired()
    except Exception:
        raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
    if expired:
        raise _local_invalid("TASK_CREDENTIAL_EXPIRED")
    return snapshot


def _task_definition_snapshot(value: Any) -> TaskDefinitionReference:
    """Return a detached frozen Definition reference for one status read."""

    if type(value) is not TaskDefinitionReference:
        raise _local_invalid()
    try:
        snapshot = value._validated_snapshot()
    except Exception:
        raise _local_invalid() from None
    return snapshot


def _task_reward_snapshot(value: Any) -> AgentTaskRewardTerms:
    """Return a detached frozen Claim reward snapshot for status verification."""

    if type(value) is not AgentTaskRewardTerms:
        raise _local_invalid()
    try:
        snapshot = AgentTaskRewardTerms.model_validate(
            value.model_dump(mode="python"),
            strict=True,
        )
    except Exception:
        raise _local_invalid() from None
    return snapshot


def _safe_random_jitter(
    random_source: Callable[[], float],
) -> float:
    try:
        value = float(random_source())
    except Exception:
        return 0.0
    if not math.isfinite(value):
        return 0.0
    return min(1.0, max(0.0, value)) * 0.25


def _reject_claim_token_in_public_value(value: Any, claim_token: str) -> None:
    """Fail closed if a scoped credential is copied into a public field."""

    if type(value) is str:
        if claim_token in value:
            raise ValueError("Invalid public Task value.")
        return
    if type(value) is dict:
        for key, item in value.items():
            _reject_claim_token_in_public_value(key, claim_token)
            _reject_claim_token_in_public_value(item, claim_token)
        return
    if type(value) in {list, tuple}:
        for item in value:
            _reject_claim_token_in_public_value(item, claim_token)


def _credential_local_fingerprint(credential: TaskClaimCredential) -> str:
    """Return a non-authoritative, one-way binding for a validated credential."""

    try:
        return credential._local_fingerprint()
    except Exception:
        raise _local_invalid("TASK_CREDENTIAL_INVALID") from None


def _guided_checkpoint_snapshot(
    value: Union[
        TaskDomainObservationCheckpoint, Mapping[str, Any]
    ],
) -> TaskDomainObservationCheckpoint:
    candidate: Optional[Dict[str, Any]] = None
    try:
        if type(value) is TaskDomainObservationCheckpoint:
            return value._validated_snapshot()
        if not isinstance(value, Mapping):
            raise ValueError
        candidate = copy.deepcopy(dict(value))
        checkpoint = TaskDomainObservationCheckpoint.model_validate(
            candidate,
            strict=True,
        )
        return checkpoint._validated_snapshot()
    except Exception:
        raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
    finally:
        candidate = None


def _checkpoint_state_value(
    checkpoint: TaskDomainObservationCheckpoint,
) -> str:
    state = checkpoint.state
    if isinstance(state, TaskDomainObservationCheckpointState):
        return state.value
    if type(state) is str:
        return state
    raise _local_invalid("TASK_CREDENTIAL_INVALID")


class AgentTaskClient:
    """Synchronous Task client with no wallet, signer, or payment capability."""

    api_origin = PUBLIC_API_ORIGIN

    @_public_client_error_boundary
    def __init__(
        self,
        api_origin: str = PUBLIC_API_ORIGIN,
        *,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 10.0,
        write_timeout_seconds: float = 10.0,
        pool_timeout_seconds: float = 5.0,
        total_operation_timeout_seconds: float = 20.0,
        _transport: Optional[TaskTransport] = None,
        _sleep: Callable[[float], None] = time.sleep,
        _monotonic: Callable[[], float] = time.monotonic,
        _random: Callable[[], float] = random.random,
    ) -> None:
        try:
            validate_fixed_api_origin(api_origin)
        except (TypeError, ValueError):
            raise TaskTransportError(
                "TASK_ORIGIN_INVALID", request_bytes_sent=False
            ) from None
        if _transport is not None:
            injected_origin = getattr(_transport, "api_origin", PUBLIC_API_ORIGIN)
            if injected_origin != PUBLIC_API_ORIGIN:
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
            self._transport = _transport
        else:
            self._transport = TaskTransport(
                api_origin=api_origin,
                connect_timeout_seconds=connect_timeout_seconds,
                read_timeout_seconds=read_timeout_seconds,
                write_timeout_seconds=write_timeout_seconds,
                pool_timeout_seconds=pool_timeout_seconds,
                total_operation_timeout_seconds=(
                    total_operation_timeout_seconds
                ),
            )
        self._sleep = _sleep
        self._monotonic = _monotonic
        self._random = _random
        self._closed = False

    @_public_client_error_boundary
    def __enter__(self) -> "AgentTaskClient":
        self._require_open()
        return self

    @_public_client_error_boundary
    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @_public_client_error_boundary
    def close(self) -> None:
        if not self._closed:
            try:
                self._transport.close()
            finally:
                self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            )

    def _transport_request(
        self,
        method: str,
        path: str,
        *,
        _total_timeout_seconds: Optional[float] = None,
        **kwargs: Any
    ) -> TaskTransportResponse:
        if _total_timeout_seconds is not None:
            kwargs["_total_timeout_seconds"] = _total_timeout_seconds
        try:
            return self._transport.request(method, path, **kwargs)
        except TaskError:
            raise
        except Exception:
            # A package-private injected transport is still not allowed to
            # leak mock response text, tokens, or underlying exceptions.
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=None
            ) from None

    @_public_client_error_boundary
    def list_tasks(
        self,
        task_type: str = TASK_TYPE_PAYMENT_SURFACE_DISCOVERY,
        status: str = "OPEN",
        limit: int = 20,
        cursor: Optional[str] = None,
    ) -> AgentTaskPage:
        self._require_open()
        try:
            query = AgentTaskListQuery(
                task_type=task_type,
                status=status,
                limit=limit,
                cursor=cursor,
            )
            params = query.model_dump(mode="json", exclude_none=True)
        except (TypeError, ValueError, ValidationError):
            raise _local_invalid() from None
        response = self._transport_request(
            "GET",
            TASK_LIST_PATH,
            params=params,
            maximum_attempts=3,
        )
        return _response_model(AgentTaskPage, _response_payload(response))

    def _get_task(
        self,
        task_id: str,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        _total_timeout_seconds: Optional[float] = None,
        _exchange_budget: Optional[_TaskExchangeBudget] = None,
    ) -> AgentTask:
        self._require_open()
        try:
            canonical_task_id = validate_task_id(task_id)
            path = task_detail_path(canonical_task_id)
            query = AgentTaskDetailQuery(limit=limit, cursor=cursor)
            params = query.model_dump(mode="json", exclude_none=True)
        except (TypeError, ValueError, ValidationError):
            raise _local_invalid() from None
        response = self._transport_request(
            "GET",
            path,
            params=params,
            maximum_attempts=3,
            _total_timeout_seconds=_total_timeout_seconds,
            _exchange_budget=_exchange_budget,
        )
        task = _response_model(AgentTask, _response_payload(response))
        if task.task_id != canonical_task_id:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            )
        return task

    @_public_client_error_boundary
    def get_task(
        self,
        task_id: str,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
    ) -> AgentTask:
        return self._get_task(task_id, limit=limit, cursor=cursor)

    @_public_client_error_boundary
    def claim_task(
        self,
        task_id: str,
        *,
        agent_id: str,
        reward_address: str,
    ) -> AgentTaskClaim:
        self._require_open()
        try:
            canonical_task_id = validate_task_id(task_id)
            request = AgentTaskClaimRequest(
                agent_id=agent_id,
                reward_address=reward_address,
            )
            payload = request.model_dump(mode="json")
        except (TypeError, ValueError, ValidationError):
            raise _local_invalid() from None

        try:
            response = self._transport_request(
                "POST",
                task_claim_path(canonical_task_id),
                json_body=payload,
                maximum_attempts=1,
                ambiguous_delivery_code="CLAIM_OUTCOME_UNKNOWN",
            )
        except TaskAmbiguousOutcomeError:
            raise
        except TaskError as error:
            if error.request_bytes_sent is False or error.mutation_free:
                raise
            raise TaskAmbiguousOutcomeError(
                "CLAIM_OUTCOME_UNKNOWN",
                status_code=error.status_code,
                request_bytes_sent=error.request_bytes_sent,
                retry_after_seconds=error.retry_after_seconds,
            ) from None
        try:
            wire_claim = AgentTaskClaimResponse.model_validate(
                _claim_response_payload(response)
            )
            if (
                wire_claim.task_id != canonical_task_id
                or wire_claim.reward_address != request.reward_address
            ):
                raise ValueError
            claim = wire_claim.to_claim(
                agent_id=request.agent_id,
                api_origin=PUBLIC_API_ORIGIN,
            )
            claim_reward = _task_reward_snapshot(wire_claim.reward)
            if (
                claim.reward != claim_reward
                or claim.credential.reward != claim_reward
            ):
                raise ValueError
            claim_token = claim.credential._claim_token_value()
            _reject_claim_token_in_public_value(
                claim.model_dump(mode="json"),
                claim_token,
            )
            return claim
        except (
            TaskError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            # A malformed 200 may follow a committed Claim.  Never issue a
            # recovery Claim or expose the raw response/token.
            raise TaskAmbiguousOutcomeError(
                "CLAIM_OUTCOME_UNKNOWN",
                status_code=getattr(response, "status_code", 200),
                request_bytes_sent=True,
            ) from None

    def _submit_domain_observation_snapshot(
        self,
        credential: TaskClaimCredential,
        request: TaskDomainObservationSubmission,
        *,
        _exchange_budget: Optional[_TaskExchangeBudget] = None,
    ) -> TaskDomainObservationResponse:
        try:
            request.canonical_digest()
            payload = copy.deepcopy(
                request.model_dump(mode="json")
            )
            # Keep the exact body supplied to the transport independently
            # strict and bounded as well.
            TaskDomainObservationSubmission.model_validate(
                payload,
                strict=True,
            )
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None

        claim_token: Optional[str] = None
        try:
            try:
                claim_token = credential._claim_token_value()
                _reject_claim_token_in_public_value(payload, claim_token)
            except Exception:
                raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
            try:
                budget_kwargs: Dict[str, Any] = {}
                if _exchange_budget is not None:
                    budget_kwargs["_exchange_budget"] = _exchange_budget
                response = self._transport_request(
                    "POST",
                    task_observation_path(credential.task_id),
                    json_body=payload,
                    claim_token=claim_token,
                    maximum_attempts=2,
                    ambiguous_delivery_code="SUBMISSION_OUTCOME_UNKNOWN",
                    **budget_kwargs,
                )
            except TaskAmbiguousOutcomeError:
                raise
            except TaskError as error:
                if (
                    error.request_bytes_sent is False
                    or (
                        isinstance(error, TaskAPIError)
                        and error.public_error_code is not None
                        and error.status_code is not None
                        and 400 <= error.status_code < 500
                        and error.status_code != 429
                    )
                ):
                    raise
                raise TaskAmbiguousOutcomeError(
                    "SUBMISSION_OUTCOME_UNKNOWN",
                    status_code=error.status_code,
                    request_bytes_sent=error.request_bytes_sent,
                    retry_after_seconds=error.retry_after_seconds,
                ) from None
        finally:
            claim_token = None

        try:
            result = _response_model(
                TaskDomainObservationResponse,
                _response_payload(response),
            )
            if (
                result.task_id != credential.task_id
                or result.submission_id != request.submission_id
            ):
                raise ValueError
            response_token = credential._claim_token_value()
            _reject_claim_token_in_public_value(
                result.model_dump(mode="json"),
                response_token,
            )
            return result
        except (
            TaskError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            raise TaskAmbiguousOutcomeError(
                "SUBMISSION_OUTCOME_UNKNOWN",
                status_code=getattr(response, "status_code", 200),
                request_bytes_sent=True,
            ) from None

    @_public_client_error_boundary
    def submit_domain_observation(
        self,
        credential: TaskClaimCredential,
        submission: Union[
            TaskDomainObservationSubmission, Mapping[str, Any]
        ],
    ) -> TaskDomainObservationResponse:
        self._require_open()
        credential = _credential_is_active(credential)
        try:
            # Pydantic models remain mutable for compatibility, and callers
            # can mutate a validated list in place without assignment
            # validation.  Detach a fresh snapshot and strictly revalidate it
            # immediately before JCS serialization and transport.
            request = TaskDomainObservationSubmission._validated_snapshot(
                submission
            )
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
        return self._submit_domain_observation_snapshot(
            credential,
            request,
        )

    def _completion_fallback_status(
        self,
        credential: TaskClaimCredential,
        request: AgentTaskCompletionRequest,
        ambiguous: TaskAmbiguousOutcomeError,
        *,
        _exchange_budget: Optional[_TaskExchangeBudget] = None,
    ) -> AgentTaskRewardStatus:
        # Exactly one logical public Submission-status read.  The Claim token
        # is neither needed nor sent, and Task detail is never substituted for
        # this Claim-specific receipt.
        try:
            status = self._get_reward_status(
                credential.task_id,
                submission_id=request.submission_id,
                observation_id=request.observation_id,
                task_definition=credential.task_definition,
                reward=credential.reward,
                _exchange_budget=_exchange_budget,
            )
        except TaskError:
            raise ambiguous
        if status.task_status in {
            "SUBMITTED",
            "EVALUATION_REJECTED",
            "REWARD_PENDING",
            "REWARDED",
            "REWARD_FAILED",
            "REWARD_AMBIGUOUS",
        }:
            return status
        raise ambiguous

    def _complete_task_snapshot(
        self,
        credential: TaskClaimCredential,
        request: AgentTaskCompletionRequest,
        *,
        _exchange_budget: Optional[_TaskExchangeBudget] = None,
    ) -> Tuple[
        Optional[AgentTaskCompletionResponse],
        Optional[AgentTaskRewardStatus],
    ]:
        try:
            payload = request.model_dump(mode="json")
        except (TypeError, ValueError, ValidationError):
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None

        claim_token: Optional[str] = None
        try:
            try:
                claim_token = credential._claim_token_value()
                _reject_claim_token_in_public_value(payload, claim_token)
            except Exception:
                raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
            try:
                budget_kwargs = {}
                if _exchange_budget is not None:
                    budget_kwargs["_exchange_budget"] = _exchange_budget
                response = self._transport_request(
                    "POST",
                    task_completion_path(credential.task_id),
                    json_body=payload,
                    claim_token=claim_token,
                    maximum_attempts=2,
                    ambiguous_delivery_code="COMPLETION_OUTCOME_UNKNOWN",
                    **budget_kwargs,
                )
            except TaskAmbiguousOutcomeError as ambiguous:
                return None, self._completion_fallback_status(
                    credential,
                    request,
                    ambiguous,
                    _exchange_budget=_exchange_budget,
                )
            except TaskError as error:
                if (
                    error.request_bytes_sent is False
                    or (
                        isinstance(error, TaskAPIError)
                        and error.public_error_code is not None
                        and error.status_code is not None
                        and 400 <= error.status_code < 500
                        and error.status_code != 429
                    )
                ):
                    raise
                ambiguous = TaskAmbiguousOutcomeError(
                    "COMPLETION_OUTCOME_UNKNOWN",
                    status_code=error.status_code,
                    request_bytes_sent=error.request_bytes_sent,
                    retry_after_seconds=error.retry_after_seconds,
                )
                return None, self._completion_fallback_status(
                    credential,
                    request,
                    ambiguous,
                    _exchange_budget=_exchange_budget,
                )
        finally:
            claim_token = None

        try:
            result = _response_model(
                AgentTaskCompletionResponse,
                _response_payload(response),
            )
            if (
                result.task_id != credential.task_id
                or result.submission_id != request.submission_id
                or result.observation_id != request.observation_id
            ):
                raise ValueError
            # A valid 2xx is only a durable receipt for the submitted
            # Submission/CompletionReport.  It says nothing about evaluation,
            # settlement, or reward terminality.
            response_token = credential._claim_token_value()
            _reject_claim_token_in_public_value(
                result.model_dump(mode="json"),
                response_token,
            )
            return result, None
        except (
            TaskError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            ambiguous = TaskAmbiguousOutcomeError(
                "COMPLETION_OUTCOME_UNKNOWN",
                status_code=getattr(response, "status_code", 200),
                request_bytes_sent=True,
            )
            return None, self._completion_fallback_status(
                credential,
                request,
                ambiguous,
                _exchange_budget=_exchange_budget,
            )

    @staticmethod
    def _completion_receipt_from_matched_status(
        credential: TaskClaimCredential,
        request: AgentTaskCompletionRequest,
    ) -> AgentTaskCompletionResponse:
        """Preserve the low-level API's historical reconciled response."""

        return AgentTaskCompletionResponse(
            schema_version="ln_church.agent_task_completion_response.v1",
            accepted=True,
            task_id=credential.task_id,
            submission_id=request.submission_id,
            observation_id=request.observation_id,
            status="SUBMITTED",
        )

    @_public_client_error_boundary
    def complete_task(
        self,
        credential: TaskClaimCredential,
        *,
        submission_id: str,
        observation_id: str,
    ) -> AgentTaskCompletionResponse:
        self._require_open()
        credential = _credential_is_active(credential)
        try:
            request = AgentTaskCompletionRequest(
                submission_id=validate_submission_id(submission_id),
                observation_id=validate_observation_id(observation_id),
            )
        except (TypeError, ValueError, ValidationError):
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
        completion_receipt, matched_status = self._complete_task_snapshot(
            credential,
            request,
        )
        if completion_receipt is not None:
            return completion_receipt
        if matched_status is None:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            )
        return self._completion_receipt_from_matched_status(
            credential,
            request,
        )

    @staticmethod
    def _guided_checkpoint_fields(
        credential: TaskClaimCredential,
        submission: TaskDomainObservationSubmission,
        *,
        submission_sha256: str,
        credential_fingerprint: str,
    ) -> Dict[str, Any]:
        return {
            "api_origin": credential.api_origin,
            "task_id": credential.task_id,
            "task_type": credential.task_type,
            "task_definition_version": (
                credential.task_definition_version
            ),
            "task_definition_digest": (
                credential.task_definition_digest
            ),
            "manifest_url": credential.manifest_url,
            "manifest_sha256": credential.manifest_sha256,
            "agent_id": credential.agent_id,
            "reward_address": credential.reward_address,
            "reward": credential.reward.model_dump(mode="python"),
            "lease_expires_at": credential.lease_expires_at,
            "submission": submission.model_dump(mode="python"),
            "submission_id": submission.submission_id,
            "submission_sha256": submission_sha256,
            "credential_fingerprint": credential_fingerprint,
        }

    @staticmethod
    def _guided_submission_snapshot(
        submission: Union[
            TaskDomainObservationSubmission, Mapping[str, Any]
        ],
        checkpoint: Optional[TaskDomainObservationCheckpoint],
    ) -> TaskDomainObservationSubmission:
        candidate: Any = submission
        copied: Optional[Dict[str, Any]] = None
        try:
            # A restart must not evaluate the model's submission-id default.
            # If an observation JSON omits it, bind that JSON to the ID already
            # held by the checkpoint before strict validation.
            if (
                checkpoint is not None
                and isinstance(submission, Mapping)
                and not isinstance(
                    submission, TaskDomainObservationSubmission
                )
            ):
                copied = copy.deepcopy(dict(submission))
                if "submission_id" not in copied:
                    copied["submission_id"] = checkpoint.submission_id
                candidate = copied
            return TaskDomainObservationSubmission._validated_snapshot(
                candidate
            )
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
        finally:
            candidate = None
            copied = None

    @staticmethod
    def _validate_guided_checkpoint_binding(
        checkpoint: TaskDomainObservationCheckpoint,
        credential: TaskClaimCredential,
        supplied_submission: TaskDomainObservationSubmission,
        *,
        submission_sha256: str,
        credential_fingerprint: str,
    ) -> TaskDomainObservationSubmission:
        try:
            stored_submission = (
                TaskDomainObservationSubmission._validated_snapshot(
                    checkpoint.submission
                )
            )
            stored_digest = stored_submission.canonical_digest_hex()
            supplied_bytes = supplied_submission.canonical_bytes()
            stored_bytes = stored_submission.canonical_bytes()
            if (
                checkpoint.api_origin != PUBLIC_API_ORIGIN
                or checkpoint.api_origin != credential.api_origin
                or checkpoint.task_id != credential.task_id
                or checkpoint.task_type != credential.task_type
                or checkpoint.task_definition != credential.task_definition
                or checkpoint.agent_id != credential.agent_id
                or checkpoint.reward_address != credential.reward_address
                or checkpoint.reward != credential.reward
                or checkpoint.lease_expires_at
                != credential.lease_expires_at
                or checkpoint.credential_fingerprint
                != credential_fingerprint
                or checkpoint.submission_id
                != stored_submission.submission_id
                or checkpoint.submission_id
                != supplied_submission.submission_id
                or checkpoint.submission_sha256 != stored_digest
                or checkpoint.submission_sha256
                != submission_sha256
                or supplied_bytes != stored_bytes
            ):
                raise ValueError
            state = _checkpoint_state_value(checkpoint)
            receipt = checkpoint.register_receipt
            if state == "REGISTER_PENDING":
                if (
                    receipt is not None
                    or checkpoint.observation_id is not None
                ):
                    raise ValueError
            elif state == "REGISTERED":
                if (
                    type(receipt) is not TaskDomainObservationResponse
                    or receipt.task_id != checkpoint.task_id
                    or receipt.submission_id
                    != checkpoint.submission_id
                    or checkpoint.observation_id
                    != receipt.observation_id
                ):
                    raise ValueError
            else:
                raise ValueError
            return stored_submission
        except TaskError:
            raise
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None

    @staticmethod
    def _emit_guided_checkpoint(
        checkpoint_sink: Optional[
            Callable[[TaskDomainObservationCheckpoint], None]
        ],
        checkpoint: TaskDomainObservationCheckpoint,
        *,
        request_bytes_sent: bool,
    ) -> None:
        if checkpoint_sink is None:
            return
        try:
            emitted = _guided_checkpoint_snapshot(checkpoint)
            checkpoint_sink(emitted)
        except TaskError:
            raise
        except Exception:
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR",
                request_bytes_sent=request_bytes_sent,
            ) from None

    @_public_client_error_boundary
    def submit_and_complete_domain_observation(
        self,
        credential: TaskClaimCredential,
        submission: Union[
            TaskDomainObservationSubmission, Mapping[str, Any]
        ],
        *,
        checkpoint: Optional[
            Union[
                TaskDomainObservationCheckpoint,
                Mapping[str, Any],
            ]
        ] = None,
        checkpoint_sink: Optional[
            Callable[[TaskDomainObservationCheckpoint], None]
        ] = None,
    ) -> TaskDomainObservationGuidedResult:
        """Register an observation and deterministically report Completion."""

        self._require_open()
        if checkpoint_sink is not None and not callable(checkpoint_sink):
            raise _local_invalid()
        credential_snapshot = _credential_is_active(credential)
        raw_checkpoint: Any = None
        raw_checkpoint_token: Optional[str] = None
        try:
            if checkpoint is not None:
                raw_checkpoint_token = (
                    credential_snapshot._claim_token_value()
                )
                if type(checkpoint) is TaskDomainObservationCheckpoint:
                    raw_checkpoint = checkpoint.model_dump(mode="json")
                elif isinstance(checkpoint, Mapping):
                    raw_checkpoint = copy.deepcopy(dict(checkpoint))
                else:
                    raise ValueError
                _reject_claim_token_in_public_value(
                    raw_checkpoint,
                    raw_checkpoint_token,
                )
        except TaskError:
            raise
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
        finally:
            raw_checkpoint_token = None
            if type(raw_checkpoint) is dict:
                raw_checkpoint.clear()
            raw_checkpoint = None
        checkpoint_snapshot = (
            None
            if checkpoint is None
            else _guided_checkpoint_snapshot(checkpoint)
        )
        submission_snapshot = self._guided_submission_snapshot(
            submission,
            checkpoint_snapshot,
        )
        claim_token: Optional[str] = None
        try:
            # The guided path persists the validated submission before the
            # existing Register boundary runs.  Apply the same fail-closed
            # secret check before any checkpoint can reach its sink, and scan
            # a supplied restart checkpoint as well.
            claim_token = credential_snapshot._claim_token_value()
            _reject_claim_token_in_public_value(
                credential_snapshot.model_dump(mode="json"),
                claim_token,
            )
            _reject_claim_token_in_public_value(
                submission_snapshot.model_dump(mode="json"),
                claim_token,
            )
            if checkpoint_snapshot is not None:
                _reject_claim_token_in_public_value(
                    checkpoint_snapshot.model_dump(mode="json"),
                    claim_token,
                )
            submission_sha256 = (
                submission_snapshot.canonical_digest_hex()
            )
            credential_fingerprint = _credential_local_fingerprint(
                credential_snapshot
            )
            exchange_budget = _TaskExchangeBudget(10)
        except TaskError:
            raise
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
        finally:
            claim_token = None

        if checkpoint_snapshot is None:
            try:
                checkpoint_snapshot = TaskDomainObservationCheckpoint(
                    state=(
                        TaskDomainObservationCheckpointState.REGISTER_PENDING
                    ),
                    register_receipt=None,
                    observation_id=None,
                    **self._guided_checkpoint_fields(
                        credential_snapshot,
                        submission_snapshot,
                        submission_sha256=submission_sha256,
                        credential_fingerprint=credential_fingerprint,
                    )
                )
                checkpoint_snapshot = _guided_checkpoint_snapshot(
                    checkpoint_snapshot
                )
            except TaskError:
                raise
            except Exception:
                raise _local_invalid("TASK_CREDENTIAL_INVALID") from None

        stored_submission = self._validate_guided_checkpoint_binding(
            checkpoint_snapshot,
            credential_snapshot,
            submission_snapshot,
            submission_sha256=submission_sha256,
            credential_fingerprint=credential_fingerprint,
        )
        state = _checkpoint_state_value(checkpoint_snapshot)
        register_receipt: TaskDomainObservationResponse
        if state == "REGISTER_PENDING":
            self._emit_guided_checkpoint(
                checkpoint_sink,
                checkpoint_snapshot,
                request_bytes_sent=False,
            )
            register_receipt = self._submit_domain_observation_snapshot(
                credential_snapshot,
                stored_submission,
                _exchange_budget=exchange_budget,
            )
            try:
                checkpoint_snapshot = TaskDomainObservationCheckpoint(
                    state=TaskDomainObservationCheckpointState.REGISTERED,
                    register_receipt=register_receipt.model_dump(
                        mode="python"
                    ),
                    observation_id=register_receipt.observation_id,
                    **self._guided_checkpoint_fields(
                        credential_snapshot,
                        stored_submission,
                        submission_sha256=submission_sha256,
                        credential_fingerprint=credential_fingerprint,
                    )
                )
                checkpoint_snapshot = _guided_checkpoint_snapshot(
                    checkpoint_snapshot
                )
            except TaskError:
                raise
            except Exception:
                raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
            stored_submission = self._validate_guided_checkpoint_binding(
                checkpoint_snapshot,
                credential_snapshot,
                submission_snapshot,
                submission_sha256=submission_sha256,
                credential_fingerprint=credential_fingerprint,
            )
            self._emit_guided_checkpoint(
                checkpoint_sink,
                checkpoint_snapshot,
                request_bytes_sent=True,
            )
        elif state == "REGISTERED":
            register_receipt = checkpoint_snapshot.register_receipt
        else:
            raise _local_invalid("TASK_CREDENTIAL_INVALID")

        # Completion IDs are derived only from the strictly validated Register
        # receipt.  No caller-provided Completion identifier reaches this body.
        try:
            if (
                register_receipt.task_id != credential_snapshot.task_id
                or register_receipt.submission_id
                != stored_submission.submission_id
                or register_receipt.submission_id
                != checkpoint_snapshot.submission_id
            ):
                raise ValueError
            completion_request = AgentTaskCompletionRequest(
                submission_id=register_receipt.submission_id,
                observation_id=register_receipt.observation_id,
            )
        except Exception:
            raise _local_invalid("TASK_CREDENTIAL_INVALID") from None
        completion_receipt, matched_status = self._complete_task_snapshot(
            credential_snapshot,
            completion_request,
            _exchange_budget=exchange_budget,
        )
        result_token: Optional[str] = None
        try:
            result_token = credential_snapshot._claim_token_value()
            _reject_claim_token_in_public_value(
                register_receipt.model_dump(mode="json"),
                result_token,
            )
            if completion_receipt is not None:
                _reject_claim_token_in_public_value(
                    completion_receipt.model_dump(mode="json"),
                    result_token,
                )
            if matched_status is not None:
                _reject_claim_token_in_public_value(
                    matched_status.model_dump(mode="json"),
                    result_token,
                )
            return TaskDomainObservationGuidedResult(
                register_receipt=register_receipt,
                completion_receipt=completion_receipt,
                matched_status=matched_status,
            )
        except Exception:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            ) from None
        finally:
            result_token = None

    def _get_reward_status(
        self,
        task_id: str,
        *,
        submission_id: str,
        observation_id: str,
        task_definition: TaskDefinitionReference,
        reward: AgentTaskRewardTerms,
        _total_timeout_seconds: Optional[float] = None,
        _exchange_budget: Optional[_TaskExchangeBudget] = None,
    ) -> AgentTaskRewardStatus:
        self._require_open()
        try:
            canonical_task_id = validate_task_id(task_id)
            canonical_submission_id = validate_submission_id(submission_id)
            canonical_observation_id = validate_observation_id(observation_id)
            path = task_submission_status_path(
                canonical_task_id,
                canonical_submission_id,
            )
        except (TypeError, ValueError):
            raise _local_invalid() from None
        expected_definition = _task_definition_snapshot(task_definition)
        expected_reward = _task_reward_snapshot(reward)
        response = self._transport_request(
            "GET",
            path,
            maximum_attempts=3,
            _total_timeout_seconds=_total_timeout_seconds,
            _exchange_budget=_exchange_budget,
        )
        status = _response_model(
            AgentTaskRewardStatus,
            _response_payload(response),
        )
        if (
            status.task_id != canonical_task_id
            or status.submission_id != canonical_submission_id
            or status.observation_id != canonical_observation_id
            or status.task_definition != expected_definition
            or status.network != expected_reward.network
            or status.asset != expected_reward.asset
            or status.asset_address != expected_reward.asset_address
            or status.amount_atomic != expected_reward.amount_atomic
        ):
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            )
        return status

    @_public_client_error_boundary
    def get_reward_status(
        self,
        task_id: str,
        *,
        submission_id: str,
        observation_id: str,
        task_definition: TaskDefinitionReference,
        reward: AgentTaskRewardTerms,
    ) -> AgentTaskRewardStatus:
        return self._get_reward_status(
            task_id,
            submission_id=submission_id,
            observation_id=observation_id,
            task_definition=task_definition,
            reward=reward,
        )

    @staticmethod
    def _reward_poll_error_retryable(error: TaskError) -> bool:
        if isinstance(error, TaskAPIError):
            return (
                error.status_code == 429
                and error.public_error_code == "rate_limited"
            )
        if error.code == "TASK_TIMEOUT":
            return True
        if error.code != "TASK_TRANSPORT_ERROR":
            return False
        return bool(error._retryable_transport) or error.status_code in {
            502,
            503,
            504,
        }

    @_public_client_error_boundary
    def wait_for_reward(
        self,
        task_id: str,
        *,
        submission_id: str,
        observation_id: str,
        task_definition: TaskDefinitionReference,
        reward: AgentTaskRewardTerms,
        timeout_seconds: float = 300,
        max_attempts: int = 10,
    ) -> AgentTaskRewardStatus:
        self._require_open()
        try:
            canonical_task_id = validate_task_id(task_id)
            canonical_submission_id = validate_submission_id(submission_id)
            canonical_observation_id = validate_observation_id(observation_id)
        except (TypeError, ValueError):
            raise _local_invalid() from None
        expected_definition = _task_definition_snapshot(task_definition)
        expected_reward = _task_reward_snapshot(reward)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or float(timeout_seconds) <= 0.0
            or type(max_attempts) is not int
            or not 1 <= max_attempts <= 10
        ):
            raise _local_invalid()

        try:
            deadline = float(self._monotonic()) + float(timeout_seconds)
            exchange_budget = _TaskExchangeBudget(max_attempts)
        except Exception:
            raise TaskTransportError("TASK_TRANSPORT_ERROR") from None

        last_pending: Optional[AgentTaskRewardStatus] = None
        for attempt in range(max_attempts):
            if exchange_budget.remaining <= 0:
                break
            try:
                remaining = deadline - float(self._monotonic())
            except Exception:
                raise TaskTransportError("TASK_TRANSPORT_ERROR") from None
            if not math.isfinite(remaining) or remaining <= 0.0:
                break

            retry_after: Optional[float] = None
            try:
                status = self._get_reward_status(
                    canonical_task_id,
                    submission_id=canonical_submission_id,
                    observation_id=canonical_observation_id,
                    task_definition=expected_definition,
                    reward=expected_reward,
                    _total_timeout_seconds=remaining,
                    _exchange_budget=exchange_budget,
                )
            except TaskError as error:
                if not self._reward_poll_error_retryable(error):
                    raise
                retry_after = error.retry_after_seconds
            else:
                try:
                    observed_at = float(self._monotonic())
                except Exception:
                    raise TaskTransportError(
                        "TASK_TRANSPORT_ERROR"
                    ) from None
                if not math.isfinite(observed_at):
                    raise TaskTransportError(
                        "TASK_TRANSPORT_ERROR"
                    )
                if status.reward_state in {
                    "not_eligible",
                    "paid",
                    "failed",
                    "ambiguous",
                }:
                    return status
                last_pending = status
                if observed_at > deadline:
                    break

            if exchange_budget.remaining <= 0:
                break
            if attempt + 1 >= max_attempts:
                break

            exponential = min(30.0, float(2 ** attempt))
            if (
                retry_after is not None
                and isinstance(retry_after, (int, float))
                and not isinstance(retry_after, bool)
                and math.isfinite(float(retry_after))
                and 0.0 <= float(retry_after) <= 30.0
            ):
                base_delay = float(retry_after)
            else:
                base_delay = exponential
            delay = base_delay + _safe_random_jitter(self._random)

            try:
                remaining = deadline - float(self._monotonic())
            except Exception:
                raise TaskTransportError("TASK_TRANSPORT_ERROR") from None
            if (
                not math.isfinite(remaining)
                or remaining <= 0.0
                or delay >= remaining
            ):
                break
            try:
                self._sleep(delay)
            except Exception:
                raise TaskTransportError(
                    "TASK_TRANSPORT_ERROR"
                ) from None

        if last_pending is not None:
            return last_pending
        raise TaskTransportError("TASK_TIMEOUT")


__all__ = [
    "AgentTaskClient",
    "TaskAPIError",
    "TaskAmbiguousOutcomeError",
    "TaskError",
    "TaskTransportError",
]
