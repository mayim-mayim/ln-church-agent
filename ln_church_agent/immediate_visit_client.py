"""Typed immediate visit client with durable, finite completion recovery."""
from __future__ import annotations

from .access_quota import AccessQuotaPolicy

import math
import time
from typing import Any, Callable, Optional

from .immediate_visit_contract import (
    CLAIM_REQUEST_SCHEMA_VERSION, ABANDON_REQUEST_SCHEMA_VERSION,
    canonical_report_bytes, parse_timestamp, positive_bound, validate_agent_id,
    validate_reward_address, validate_task_id, validate_opaque_id,
)
from .immediate_visit_models import (
    FrozenImmediateVisitReport, ImmediateVisitClaimCredential, ImmediateVisitTask,
    ImmediateVisitTaskPage, ImmediateVisitCompletionReceipt,
    ImmediateVisitSubmissionStatus, ImmediateVisitCompletionResult, ImmediateVisitAbandonmentResult,
    _ImmediateVisitAbandonmentResponse,
)
from .immediate_visit_transport import (
    ImmediateVisitTransport, ImmediateVisitError, ImmediateVisitTransportError,
    ImmediateVisitAPIError, _public_boundary,
)


def _model(model_type: Any, payload: Any) -> Any:
    try:
        return model_type.model_validate(payload)
    except Exception:
        raise ImmediateVisitTransportError("RESPONSE_INVALID", request_bytes_sent=True) from None


def _credential(value: Any) -> ImmediateVisitClaimCredential:
    if not isinstance(value, ImmediateVisitClaimCredential):
        raise ImmediateVisitTransportError("CREDENTIAL_INVALID", request_bytes_sent=False)
    try:
        return value._validated_snapshot()
    except Exception:
        raise ImmediateVisitTransportError("CREDENTIAL_INVALID", request_bytes_sent=False) from None


def _report(claim: ImmediateVisitClaimCredential, value: Any) -> FrozenImmediateVisitReport:
    if not isinstance(value, FrozenImmediateVisitReport):
        raise ImmediateVisitTransportError("REPORT_INVALID", request_bytes_sent=False)
    try:
        result = FrozenImmediateVisitReport.from_bytes(value.canonical_bytes)
        if (value.report_sha256 != result.report_sha256 or result.task_id != claim.task_id
                or result.execution_id != claim.execution_id or result.profile_id != claim.profile_id
                or result.endpoint_id not in tuple(item.endpoint_id for item in claim.endpoints)):
            raise ValueError
        return result
    except Exception:
        raise ImmediateVisitTransportError("REPORT_INVALID", request_bytes_sent=False) from None


def _bound_response(model_type: Any, payload: Any, claim: ImmediateVisitClaimCredential,
                    report: FrozenImmediateVisitReport) -> Any:
    result = _model(model_type, payload)
    if not result.matches(report) or parse_timestamp(result.received_at) >= parse_timestamp(claim.report_deadline):
        raise ImmediateVisitTransportError("RESPONSE_BINDING_INVALID", request_bytes_sent=True)
    return result


class AgentImmediateVisitClient:
    """Only Venue API operations; target acquisition belongs to the executor."""

    def __init__(self, *, transport: Optional[ImmediateVisitTransport] = None,
                 access_quota: Optional[AccessQuotaPolicy] = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if transport is not None and not isinstance(transport, ImmediateVisitTransport):
            raise ValueError("Invalid immediate visit transport.")
        self._transport = transport or ImmediateVisitTransport(access_quota=access_quota)
        self._owns_transport = transport is None
        self._monotonic = monotonic
        self._sleep = sleep
        self._closed = False

    def __enter__(self) -> "AgentImmediateVisitClient":
        self._require_open()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._owns_transport:
                self._transport.close()

    def _require_open(self) -> None:
        if self._closed:
            raise ImmediateVisitTransportError("CLIENT_CLOSED")

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if not math.isfinite(remaining) or remaining <= 0:
            return 0.0
        return remaining

    @_public_boundary
    def list_tasks(self, limit: int = 25, cursor: Optional[str] = None,
                   *, timeout_seconds: float = 20.0) -> ImmediateVisitTaskPage:
        self._require_open()
        return _model(ImmediateVisitTaskPage, self._transport.list_tasks(
            limit=limit, cursor=cursor, timeout_seconds=timeout_seconds))

    @_public_boundary
    def get_task(self, task_id: str, *, timeout_seconds: float = 20.0) -> ImmediateVisitTask:
        self._require_open()
        task_id = validate_task_id(task_id)
        task = _model(ImmediateVisitTask, self._transport.get_task(task_id, timeout_seconds=timeout_seconds))
        if task.task_id != task_id:
            raise ImmediateVisitTransportError("RESPONSE_BINDING_INVALID", request_bytes_sent=True)
        return task

    @_public_boundary
    def claim_task(self, task_id: str, agent_id: str, reward_address: str, *,
                   idempotency_key: str, timeout_seconds: float = 20.0) -> ImmediateVisitClaimCredential:
        self._require_open()
        task_id = validate_task_id(task_id)
        address = validate_reward_address(reward_address)
        key = validate_opaque_id(idempotency_key, "idempotency_key")
        body = canonical_report_bytes({"schema_version": CLAIM_REQUEST_SCHEMA_VERSION,
                                       "agent_id": validate_agent_id(agent_id), "reward_address": address})
        try:
            claim = _model(ImmediateVisitClaimCredential, self._transport.claim_task(
                task_id, body, idempotency_key=key, timeout_seconds=timeout_seconds))
            if claim.task_id != task_id or claim.reward_address != address:
                raise ImmediateVisitTransportError("RESPONSE_BINDING_INVALID", request_bytes_sent=True)
            return claim
        except ImmediateVisitTransportError as error:
            if error.request_bytes_sent is not False:
                raise ImmediateVisitTransportError("CLAIM_OUTCOME_UNKNOWN", request_bytes_sent=True) from None
            raise

    @_public_boundary
    def recover_claim(self, task_id: str, agent_id: str, reward_address: str, *,
                      idempotency_key: str, timeout_seconds: float = 20.0):
        self._require_open()
        task_id = validate_task_id(task_id)
        address = validate_reward_address(reward_address)
        body = canonical_report_bytes({"schema_version": CLAIM_REQUEST_SCHEMA_VERSION,
                                       "agent_id": validate_agent_id(agent_id), "reward_address": address})
        claim = _model(ImmediateVisitClaimCredential, self._transport.recover_claim(
            task_id, body, idempotency_key=idempotency_key, timeout_seconds=timeout_seconds))
        if claim.task_id != task_id or claim.reward_address != address:
            raise ImmediateVisitTransportError("RESPONSE_BINDING_INVALID", request_bytes_sent=True)
        return claim

    @_public_boundary
    def abandon_claim(self, claim: ImmediateVisitClaimCredential, *, idempotency_key: str,
                      timeout_seconds: float = 20.0) -> ImmediateVisitAbandonmentResult:
        self._require_open()
        claim = _credential(claim)
        body = canonical_report_bytes({"schema_version": ABANDON_REQUEST_SCHEMA_VERSION,
                                       "execution_id": claim.execution_id})
        # The accepted Hondō response supplies a task/execution witness. Check it
        # before exposing transport receipt; do not mutate local Report or rights.
        try:
            payload = self._transport.abandon_claim(claim.task_id, claim._claim_token_value(), body,
                                                   idempotency_key=idempotency_key, timeout_seconds=timeout_seconds)
            response = _model(_ImmediateVisitAbandonmentResponse, payload)
            if response.task_id != claim.task_id or response.execution_id != claim.execution_id:
                raise ImmediateVisitTransportError("RESPONSE_BINDING_INVALID", request_bytes_sent=True)
        except ImmediateVisitAPIError as error:
            return ImmediateVisitAbandonmentResult(transport_state="rejected", task_id=claim.task_id,
                                                   execution_id=claim.execution_id, error_code=error.public_error_code)
        except ImmediateVisitTransportError:
            return ImmediateVisitAbandonmentResult(transport_state="unknown", task_id=claim.task_id,
                                                   execution_id=claim.execution_id)
        return ImmediateVisitAbandonmentResult(transport_state="response_received", task_id=claim.task_id,
                                               execution_id=claim.execution_id)

    @_public_boundary
    def get_submission_status(self, claim: ImmediateVisitClaimCredential,
                              frozen_report: FrozenImmediateVisitReport, *,
                              timeout_seconds: float = 20.0) -> ImmediateVisitSubmissionStatus:
        self._require_open()
        claim = _credential(claim)
        report = _report(claim, frozen_report)
        payload = self._transport.get_submission_status(claim.task_id, report.submission_id,
                                                        claim._claim_token_value(), timeout_seconds=timeout_seconds)
        return _bound_response(ImmediateVisitSubmissionStatus, payload, claim, report)

    @_public_boundary
    def complete_task(self, claim: ImmediateVisitClaimCredential,
                      frozen_report: FrozenImmediateVisitReport, *, journal: Any,
                      max_post_requests: int = 3, timeout_seconds: float = 90.0) -> ImmediateVisitCompletionResult:
        return self._complete(claim, frozen_report, journal=journal, status_first=False,
                              max_post_requests=max_post_requests, timeout_seconds=timeout_seconds)

    @_public_boundary
    def recover_completion(self, claim: ImmediateVisitClaimCredential,
                           frozen_report: FrozenImmediateVisitReport, *, journal: Any,
                           max_post_requests: int = 3, timeout_seconds: float = 90.0) -> ImmediateVisitCompletionResult:
        return self._complete(claim, frozen_report, journal=journal, status_first=True,
                              max_post_requests=max_post_requests, timeout_seconds=timeout_seconds)

    def _complete(self, claim: ImmediateVisitClaimCredential, frozen_report: FrozenImmediateVisitReport,
                  *, journal: Any, status_first: bool, max_post_requests: int,
                  timeout_seconds: float) -> ImmediateVisitCompletionResult:
        self._require_open()
        positive_bound(max_post_requests, "max_post_requests", integer=True, maximum=3)
        positive_bound(timeout_seconds, "timeout_seconds")
        from .immediate_visit_journal import ImmediateVisitJournal
        if not isinstance(journal, ImmediateVisitJournal):
            raise ValueError("A private immediate visit journal is required.")
        claim = _credential(claim)
        report = _report(claim, frozen_report)
        deadline = self._monotonic() + float(timeout_seconds)
        posts = statuses = 0
        result = ImmediateVisitCompletionResult(state="unknown")
        with journal.completion_operation_guard():
            report = journal.prepare_report(claim, report)
            previously_dispatched = journal.completion_started(claim, report)
            maybe_accepted = previously_dispatched
            need_status = status_first or previously_dispatched
            while self._remaining(deadline) > 0:
                if need_status:
                    remaining = self._remaining(deadline)
                    if remaining <= 0:
                        break
                    statuses += 1
                    try:
                        status = self.get_submission_status(claim, report, timeout_seconds=min(20.0, remaining))
                        result = ImmediateVisitCompletionResult(state="accepted", status=status,
                                                                post_requests=posts, status_requests=statuses)
                        break
                    except ImmediateVisitAPIError as error:
                        result = ImmediateVisitCompletionResult(state="unknown", error_code=error.public_error_code,
                                                                post_requests=posts, status_requests=statuses)
                        if error.status_code == 401:
                            break
                        # A private 404 is unknown: an earlier POST can still commit.
                    except ImmediateVisitTransportError as error:
                        result = ImmediateVisitCompletionResult(state="unknown", error_code=error.code,
                                                                post_requests=posts, status_requests=statuses)
                    need_status = False
                if posts >= max_post_requests or self._remaining(deadline) <= 0:
                    break
                # Durable intent is written before the actual request. A crash
                # anywhere after this point forces status-first manual recovery.
                journal.record_dispatch(claim, report)
                remaining = self._remaining(deadline)
                if remaining <= 0:
                    break
                posts += 1
                try:
                    payload = self._transport.post_completion_bytes(
                        claim.task_id, claim._claim_token_value(), report.submission_id,
                        report.canonical_bytes, timeout_seconds=min(20.0, remaining))
                    receipt = _bound_response(ImmediateVisitCompletionReceipt, payload, claim, report)
                    result = ImmediateVisitCompletionResult(state="accepted", receipt=receipt,
                                                            post_requests=posts, status_requests=statuses)
                    break
                except ImmediateVisitAPIError as error:
                    # Only a definite rejection of the first request, with no
                    # earlier unknown dispatch, authorizes correcting a report.
                    rejected = not maybe_accepted
                    result = ImmediateVisitCompletionResult(state="rejected" if rejected else "unknown",
                                                            error_code=error.public_error_code,
                                                            post_requests=posts, status_requests=statuses)
                    break
                except ImmediateVisitTransportError as error:
                    maybe_accepted = maybe_accepted or error.request_bytes_sent is not False
                    result = ImmediateVisitCompletionResult(state="unknown", error_code=error.code,
                                                            post_requests=posts, status_requests=statuses)
                    need_status = True
            journal.record_result(claim, report, result)
            return result

    @_public_boundary
    def poll_submission_status(self, claim: ImmediateVisitClaimCredential,
                               frozen_report: FrozenImmediateVisitReport, *, max_requests: int = 5,
                               interval_seconds: float = 1.0, timeout_seconds: float = 120.0) -> ImmediateVisitCompletionResult:
        """Explicit finite polling; no target GET and no background work."""
        self._require_open()
        positive_bound(max_requests, "max_requests", integer=True)
        positive_bound(interval_seconds, "interval_seconds")
        positive_bound(timeout_seconds, "timeout_seconds")
        claim = _credential(claim)
        report = _report(claim, frozen_report)
        deadline = self._monotonic() + float(timeout_seconds)
        result = ImmediateVisitCompletionResult(state="unknown")
        for attempt in range(max_requests):
            remaining = self._remaining(deadline)
            if remaining <= 0:
                break
            try:
                status = self.get_submission_status(claim, report, timeout_seconds=min(20.0, remaining))
                result = ImmediateVisitCompletionResult(state="accepted", status=status, status_requests=attempt + 1)
                if status.evaluation_state != "pending":
                    break
            except ImmediateVisitError as error:
                code = error.public_error_code if isinstance(error, ImmediateVisitAPIError) else error.code
                result = ImmediateVisitCompletionResult(state=result.state, status=result.status,
                                                        error_code=code, status_requests=attempt + 1)
                if error.status_code == 401:
                    break
            if attempt + 1 >= max_requests or self._remaining(deadline) <= interval_seconds:
                break
            self._sleep(float(interval_seconds))
        return result


__all__ = ["AgentImmediateVisitClient"]
