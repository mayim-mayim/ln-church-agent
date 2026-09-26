"""Generic Venue client for the parallel v1.18 Task profile."""

from __future__ import annotations

from .access_quota import AccessQuotaPolicy, AccessQuotaError

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Mapping, Optional, Union

from pydantic import ValidationError

from .task_journal import JournalError, TaskJournal, derive_local_execution_id
from .task_v2_contract import (
    canonical_completion_bytes,
    parse_rfc3339_whole_second,
    validate_agent_id,
    validate_manifest_bytes,
    validate_reward_address,
    validate_submission_id,
    validate_task_id,
)
from .task_v2_models import (
    ScheduledClaimAbandonmentResult,
    ScheduledCompletionAcknowledgement,
    ScheduledCompletionReceipt,
    ScheduledCompletionReport,
    ScheduledHttpGetBatchTask,
    ScheduledHttpGetBatchTaskPage,
    ScheduledRewardStatus,
    ScheduledTaskAbandonRequest,
    ScheduledTaskClaimCredential,
    ScheduledTaskClaimRequest,
    ScheduledTaskClaimResponse,
    ScheduledTaskReadiness,
)
from .task_v2_transport import (
    CompletionOutcomeUnknownError,
    TaskV2APIError,
    TaskV2Error,
    TaskV2Transport,
    TaskV2TransportError,
)

if TYPE_CHECKING:
    from .scheduled_http_get_batch import FrozenCompletionReport


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise TaskV2TransportError(
            "TASK_V2_REQUEST_INVALID", request_bytes_sent=False
        ) from None


def _model(model_type: Any, payload: Mapping[str, Any]) -> Any:
    candidate: Dict[str, Any] = {}
    try:
        if type(payload) is not dict:
            raise ValueError
        candidate = dict(payload)
        payload = {}
        return model_type.model_validate(candidate)
    except (TypeError, ValueError, ValidationError):
        candidate.clear()
        payload = {}
        raise TaskV2TransportError(
            "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
        ) from None


def _credential(value: Any) -> ScheduledTaskClaimCredential:
    if not isinstance(value, ScheduledTaskClaimCredential):
        raise TaskV2TransportError(
            "TASK_V2_CREDENTIAL_INVALID", request_bytes_sent=False
        )
    try:
        return value._validated_snapshot()
    except Exception:
        raise TaskV2TransportError(
            "TASK_V2_CREDENTIAL_INVALID", request_bytes_sent=False
        ) from None


def _report(value: Any) -> ScheduledCompletionReport:
    if isinstance(value, ScheduledCompletionReport):
        return ScheduledCompletionReport.model_validate(value.model_dump(mode="python"))
    converter = getattr(value, "to_completion_report", None)
    if callable(converter):
        try:
            converted = converter()
        except Exception:
            raise TaskV2TransportError(
                "TASK_V2_REPORT_INVALID", request_bytes_sent=False
            ) from None
        if isinstance(converted, ScheduledCompletionReport):
            return converted
    raise TaskV2TransportError("TASK_V2_REPORT_INVALID", request_bytes_sent=False)


class AgentTaskV2Client:
    """Task/profile detection, Claim, readiness, Completion and status.

    The Scheduled HTTP adapter owns release/target I/O.  This generic client
    owns only the Venue wire and the private Claim credential boundary.
    """

    def __init__(
        self,
        *,
        transport: Optional[TaskV2Transport] = None,
        access_quota: Optional[AccessQuotaPolicy] = None,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if transport is not None and not isinstance(transport, TaskV2Transport):
            raise ValueError("Invalid v2 transport.")
        self._transport = transport or TaskV2Transport(access_quota=access_quota)
        self._owns_transport = transport is None
        self._utcnow = utcnow
        self._monotonic = monotonic
        self._sleep = sleep
        self._closed = False

    def __enter__(self) -> "AgentTaskV2Client":
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._owns_transport:
                self._transport.close()

    def _require_open(self) -> None:
        if self._closed:
            raise TaskV2TransportError("TASK_V2_CLIENT_CLOSED")

    def _now(self) -> datetime:
        try:
            value = self._utcnow()
        except Exception:
            raise TaskV2TransportError("TASK_V2_CLOCK_INVALID") from None
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise TaskV2TransportError("TASK_V2_CLOCK_INVALID")
        return value.astimezone(timezone.utc)

    def list_tasks(self) -> ScheduledHttpGetBatchTaskPage:
        self._require_open()
        return _model(ScheduledHttpGetBatchTaskPage, self._transport.list_tasks())

    def get_task(self, task_id: str) -> ScheduledHttpGetBatchTask:
        self._require_open()
        return _model(
            ScheduledHttpGetBatchTask,
            self._transport.get_task(validate_task_id(task_id)),
        )

    def claim_task(
        self,
        task_id: str,
        *,
        agent_id: str,
        reward_address: str,
    ) -> ScheduledTaskClaimCredential:
        self._require_open()
        request = ScheduledTaskClaimRequest(
            agent_id=validate_agent_id(agent_id),
            reward_address=validate_reward_address(reward_address),
        )
        payload = self._transport.claim_task(
            validate_task_id(task_id),
            _json_bytes(request.model_dump(mode="json")),
        )
        try:
            response = _model(ScheduledTaskClaimResponse, payload)
        finally:
            payload.clear()
        if response.task_id != task_id or response.reward_address != request.reward_address:
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )
        return response.to_credential(agent_id=request.agent_id)

    def get_readiness(
        self,
        credential: ScheduledTaskClaimCredential,
        *,
        journal: TaskJournal,
    ) -> ScheduledTaskReadiness:
        self._require_open()
        snapshot = _credential(credential)
        # A bearer credential is not sufficient readiness authority.  The
        # immutable definition-bound genesis must exist and match before the
        # Claim token can cross the wire.
        self._validate_journal_identity(journal, snapshot)
        readiness_states = {
            "INIT",
            "OFFER_RECHECKED",
            "MANIFEST_VERIFIED",
            "ATTEMPT_STARTED",
            "RESULT_RECORDED",
        }
        journal_snapshot = journal.load()
        if journal_snapshot.state not in readiness_states:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        payload = self._transport.get_readiness(
            snapshot.task_id, snapshot._claim_token_value()
        )
        try:
            readiness = _model(ScheduledTaskReadiness, payload)
        finally:
            payload.clear()
        if (
            readiness.task_id != snapshot.task_id
            or readiness._manifest_url_value() != snapshot._manifest_url_value()
            or readiness.manifest_url_expires_at
            != snapshot.manifest_url_expires_at
            or (
                readiness.manifest_url_not_before is not None
                and readiness.manifest_url_not_before != snapshot.scheduled_at
            )
            or (
                readiness.retry_at is not None
                and readiness.retry_at != snapshot.scheduled_at
            )
            or (
                readiness.report_close_at is not None
                and readiness.report_close_at != snapshot.report_close_at
            )
            or (
                readiness.new_target_start_before is not None
                and parse_rfc3339_whole_second(
                    readiness.new_target_start_before,
                    "new_target_start_before",
                )
                != parse_rfc3339_whole_second(
                    snapshot.scheduled_at, "scheduled_at"
                )
                + timedelta(seconds=300)
            )
        ):
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )

        # A non-null digest is disclosed only at or after T.  Accept it into
        # the execution flow only after the irreversible journal binding is
        # durably replaced.  A pre-T null may leave an unbound INIT journal,
        # but null can never erase an existing binding.
        journal_snapshot = journal.load()
        if journal_snapshot.state not in readiness_states:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        digest = readiness.manifest_sha256
        if journal_snapshot.state == "INIT":
            if digest is not None:
                journal_snapshot = journal.mark_offer_rechecked(digest)
        elif journal_snapshot.payload["manifest_sha256"] != digest:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        if digest is None:
            if (
                journal_snapshot.state != "INIT"
                or journal_snapshot.payload["manifest_sha256"] is not None
            ):
                raise JournalError("JOURNAL_STATE_CONFLICT")
        elif journal_snapshot.payload["manifest_sha256"] != digest:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        return readiness

    def abandon_claim(
        self,
        credential: ScheduledTaskClaimCredential,
        *,
        abandonment_id: str,
    ) -> ScheduledClaimAbandonmentResult:
        self._require_open()
        snapshot = _credential(credential)
        request = ScheduledTaskAbandonRequest(abandonment_id=abandonment_id)
        self._transport.abandon_claim(
            snapshot.task_id,
            snapshot._claim_token_value(),
            _json_bytes(request.model_dump(mode="json")),
        )
        return ScheduledClaimAbandonmentResult(
            abandonment_id=request.abandonment_id
        )

    @staticmethod
    def _validate_report_binding(
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
    ) -> None:
        if (
            report.task_type != credential.task_type
            or report.task_definition_version
            != credential.task_definition_version
            or report.task_definition_digest != credential.task_definition_digest
        ):
            raise TaskV2TransportError(
                "TASK_V2_REPORT_BINDING_INVALID", request_bytes_sent=False
            )

    @staticmethod
    def _validate_receipt(
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
        report_bytes: bytes,
        receipt: ScheduledCompletionReceipt,
    ) -> None:
        accepted_at = parse_rfc3339_whole_second(
            receipt.accepted_at, "accepted_at"
        )
        scheduled_at = parse_rfc3339_whole_second(
            credential.scheduled_at, "scheduled_at"
        )
        report_close_at = parse_rfc3339_whole_second(
            credential.report_close_at, "report_close_at"
        )
        if (
            receipt.task_id != credential.task_id
            or receipt.task_type != credential.task_type
            or receipt.task_definition_version
            != credential.task_definition_version
            or receipt.task_definition_digest != credential.task_definition_digest
            or receipt.manifest_sha256 != report.manifest_sha256
            or receipt.submission_id != report.submission_id
            or receipt.report_sha256 != hashlib.sha256(report_bytes).hexdigest()
            or not scheduled_at <= accepted_at < report_close_at
        ):
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )

    @staticmethod
    def _validate_status_binding(
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
        report_bytes: bytes,
        status: ScheduledRewardStatus,
    ) -> None:
        accepted_at = parse_rfc3339_whole_second(
            status.accepted_at, "accepted_at"
        )
        scheduled_at = parse_rfc3339_whole_second(
            credential.scheduled_at, "scheduled_at"
        )
        report_close_at = parse_rfc3339_whole_second(
            credential.report_close_at, "report_close_at"
        )
        if (
            status.task_id != credential.task_id
            or status.task_type != credential.task_type
            or status.task_definition_version
            != credential.task_definition_version
            or status.task_definition_digest != credential.task_definition_digest
            or status.manifest_sha256 != report.manifest_sha256
            or status.submission_id != report.submission_id
            or status.report_sha256 != hashlib.sha256(report_bytes).hexdigest()
            or not scheduled_at <= accepted_at < report_close_at
        ):
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )

    def _post_frozen(
        self,
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
        report_bytes: bytes,
    ) -> ScheduledCompletionReceipt:
        payload = self._transport.post_completion_bytes(
            credential.task_id,
            credential._claim_token_value(),
            report.submission_id,
            report_bytes,
        )
        receipt = _model(ScheduledCompletionReceipt, payload)
        self._validate_receipt(credential, report, report_bytes, receipt)
        return receipt

    @staticmethod
    def _validate_journal_identity(
        journal: TaskJournal,
        credential: ScheduledTaskClaimCredential,
    ) -> None:
        """Validate every non-secret genesis binding before journal or wire I/O."""

        if not isinstance(journal, TaskJournal):
            raise JournalError("JOURNAL_INVALID")
        credential_handle = credential.local_claim_credential_handle
        journal.require_binding(
            task_id=credential.task_id,
            local_claim_credential_handle=credential_handle,
            task_type=credential.task_type,
            task_definition_version=credential.task_definition_version,
            task_definition_digest=credential.task_definition_digest,
        )

    @staticmethod
    def _validate_journal_binding(
        journal: TaskJournal,
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
        report_bytes: bytes,
    ) -> Mapping[str, Any]:
        """Bind Completion to the one explicit durable execution journal."""

        AgentTaskV2Client._validate_journal_identity(journal, credential)
        payload = journal.load().payload
        if payload["state"] not in {
            "REPORT_FROZEN",
            "COMPOUND_COMPLETION_ACKED",
            "TERMINAL_STATUS",
        }:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        journal_bytes = journal.frozen_report_bytes()
        if (
            payload["submission_id"] != report.submission_id
            or payload["task_type"] != credential.task_type
            or payload["task_definition_version"]
            != credential.task_definition_version
            or payload["task_definition_digest"]
            != credential.task_definition_digest
            or payload["execution_id"]
            != derive_local_execution_id(
                credential.task_id,
                credential.local_claim_credential_handle,
            )
            or payload["frozen_report_sha256"]
            != hashlib.sha256(report_bytes).hexdigest()
            or not hmac.compare_digest(journal_bytes, report_bytes)
            or payload["manifest_fetch_outcome"] != report.manifest_fetch.outcome
            or payload["manifest_sha256"] != report.manifest_sha256
        ):
            raise JournalError("JOURNAL_STATE_CONFLICT")
        if report.manifest_fetch.outcome == "retrieved":
            try:
                manifest = validate_manifest_bytes(
                    journal.verified_manifest_bytes(), report.manifest_sha256
                )
            except Exception:
                raise JournalError("JOURNAL_STATE_CONFLICT") from None
            if tuple(item.target_url for item in report.results) != manifest.urls:
                raise JournalError("JOURNAL_STATE_CONFLICT")
        return payload

    @staticmethod
    def _record_compound_ack(
        journal: TaskJournal,
        acknowledgement: ScheduledCompletionAcknowledgement,
    ) -> None:
        """Persist the single compound acknowledgement terminal boundary."""

        journal.mark_compound_completion_acked(acknowledgement)
        if (
            acknowledgement.status is not None
            and acknowledgement.status.terminal
        ):
            journal.mark_terminal_status(acknowledgement.status)

    def get_submission_status(
        self, task_id: str, submission_id: str
    ) -> ScheduledRewardStatus:
        self._require_open()
        payload = self._transport.get_submission_status(
            validate_task_id(task_id), validate_submission_id(submission_id)
        )
        return _model(ScheduledRewardStatus, payload)

    def _status_or_absent(
        self, task_id: str, submission_id: str
    ) -> Optional[ScheduledRewardStatus]:
        try:
            return self.get_submission_status(task_id, submission_id)
        except TaskV2APIError as error:
            if error.status_code == 404 and error.public_error_code == "not_found":
                return None
            raise

    def _status_first_recovery(
        self,
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
        report_bytes: bytes,
        journal: TaskJournal,
    ) -> ScheduledCompletionAcknowledgement:
        status = self._status_or_absent(credential.task_id, report.submission_id)
        if status is not None:
            self._validate_status_binding(credential, report, report_bytes, status)
            acknowledgement = ScheduledCompletionAcknowledgement(
                source="status", status=status
            )
            self._record_compound_ack(journal, acknowledgement)
            return acknowledgement

        close_at = parse_rfc3339_whole_second(
            credential.report_close_at, "report_close_at"
        )
        if self._now() >= close_at:
            raise CompletionOutcomeUnknownError()

        payload = self._validate_journal_binding(
            journal, credential, report, report_bytes
        )
        if payload["state"] != "REPORT_FROZEN":
            # A concurrent process crossed the compound acknowledgement
            # boundary.  Never dispatch again from this process.
            raise CompletionOutcomeUnknownError()
        # A recovery entrypoint with no durable dispatch fact is status-only:
        # only a fresh ``complete_task`` call may reserve the first POST.  The
        # sole resend is permitted after exactly one durable attempt and this
        # same-guard canonical absence observation.
        if payload["completion_dispatch_attempts"] != 1:
            raise CompletionOutcomeUnknownError()

        # The durable counter is advanced while the top-level state remains
        # REPORT_FROZEN.  This write must complete before any request bytes.
        journal.mark_completion_dispatch_attempted()
        try:
            receipt = self._post_frozen(credential, report, report_bytes)
            acknowledgement = ScheduledCompletionAcknowledgement(
                source="receipt", receipt=receipt
            )
            self._record_compound_ack(journal, acknowledgement)
            return acknowledgement
        except CompletionOutcomeUnknownError:
            status = self._status_or_absent(
                credential.task_id, report.submission_id
            )
            if status is None:
                raise
            self._validate_status_binding(credential, report, report_bytes, status)
            acknowledgement = ScheduledCompletionAcknowledgement(
                source="status", status=status
            )
            self._record_compound_ack(journal, acknowledgement)
            return acknowledgement

    def _status_only_after_ack(
        self,
        credential: ScheduledTaskClaimCredential,
        report: ScheduledCompletionReport,
        report_bytes: bytes,
        journal: TaskJournal,
        state: str,
    ) -> ScheduledCompletionAcknowledgement:
        status = self._status_or_absent(credential.task_id, report.submission_id)
        if status is None:
            raise CompletionOutcomeUnknownError()
        self._validate_status_binding(credential, report, report_bytes, status)
        facts = journal.compound_acknowledgement_facts()
        for field in (
            "task_id",
            "task_type",
            "task_definition_version",
            "task_definition_digest",
            "manifest_sha256",
            "submission_id",
            "report_id",
            "report_sha256",
            "accepted_at",
            "receipt_state",
        ):
            if getattr(status, field) != facts[field]:
                raise TaskV2TransportError(
                    "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
                )
        if state == "TERMINAL_STATUS" and not status.terminal:
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )
        acknowledgement = ScheduledCompletionAcknowledgement(
            source="status", status=status
        )
        if state == "COMPOUND_COMPLETION_ACKED" and status.terminal:
            journal.mark_terminal_status(status)
        return acknowledgement

    def complete_task(
        self,
        credential: ScheduledTaskClaimCredential,
        report: Any,
        *,
        journal: TaskJournal,
    ) -> ScheduledCompletionAcknowledgement:
        self._require_open()
        snapshot = _credential(credential)
        frozen = _report(report)
        self._validate_report_binding(snapshot, frozen)
        report_bytes = canonical_completion_bytes(frozen.model_dump(mode="json"))
        self._validate_journal_identity(journal, snapshot)
        with journal.completion_operation_guard():
            journal_payload = self._validate_journal_binding(
                journal, snapshot, frozen, report_bytes
            )
            if journal_payload["state"] in {
                "COMPOUND_COMPLETION_ACKED",
                "TERMINAL_STATUS",
            }:
                return self._status_only_after_ack(
                    snapshot,
                    frozen,
                    report_bytes,
                    journal,
                    str(journal_payload["state"]),
                )
            if journal_payload["completion_dispatch_attempts"] > 0:
                return self._status_first_recovery(
                    snapshot, frozen, report_bytes, journal
                )

            report_close_at = parse_rfc3339_whole_second(
                snapshot.report_close_at, "report_close_at"
            )
            if self._now() >= report_close_at:
                raise CompletionOutcomeUnknownError()

            journal.mark_completion_dispatch_attempted()
            try:
                receipt = self._post_frozen(snapshot, frozen, report_bytes)
                acknowledgement = ScheduledCompletionAcknowledgement(
                    source="receipt", receipt=receipt
                )
                self._record_compound_ack(journal, acknowledgement)
                return acknowledgement
            except CompletionOutcomeUnknownError:
                return self._status_first_recovery(
                    snapshot, frozen, report_bytes, journal
                )

    def recover_completion(
        self,
        credential: ScheduledTaskClaimCredential,
        report: Any,
        *,
        journal: TaskJournal,
    ) -> ScheduledCompletionAcknowledgement:
        """Status-first recovery for a previously ambiguous frozen dispatch."""

        self._require_open()
        snapshot = _credential(credential)
        frozen = _report(report)
        self._validate_report_binding(snapshot, frozen)
        report_bytes = canonical_completion_bytes(frozen.model_dump(mode="json"))
        self._validate_journal_identity(journal, snapshot)
        with journal.completion_operation_guard():
            journal_payload = self._validate_journal_binding(
                journal, snapshot, frozen, report_bytes
            )
            if journal_payload["state"] in {
                "COMPOUND_COMPLETION_ACKED",
                "TERMINAL_STATUS",
            }:
                return self._status_only_after_ack(
                    snapshot,
                    frozen,
                    report_bytes,
                    journal,
                    str(journal_payload["state"]),
                )
            return self._status_first_recovery(
                snapshot, frozen, report_bytes, journal
            )

    def recover_interrupted_manifest_fetch(
        self,
        credential: ScheduledTaskClaimCredential,
        *,
        journal: TaskJournal,
    ) -> "FrozenCompletionReport":
        """Durably freeze a no-I/O report from MANIFEST_FETCH_STARTED.

        Credential validation stays in the generic private boundary.  Only
        non-secret task identity fields cross into the scheduled adapter; no
        readiness request or release context is constructed on this path.
        """

        self._require_open()
        snapshot = _credential(credential)
        self._validate_journal_identity(journal, snapshot)
        credential_handle = snapshot.local_claim_credential_handle
        from .scheduled_http_get_batch import ScheduledHTTPGetBatchExecutor

        payload = journal.load().payload
        if (
            payload["state"] != "MANIFEST_FETCH_STARTED"
            or type(payload["manifest_sha256"]) is not str
            or payload["task_type"] != snapshot.task_type
            or payload["task_definition_version"]
            != snapshot.task_definition_version
            or payload["task_definition_digest"]
            != snapshot.task_definition_digest
        ):
            raise JournalError("JOURNAL_STATE_CONFLICT")
        return ScheduledHTTPGetBatchExecutor().recover_interrupted_manifest_fetch(
            task_id=snapshot.task_id,
            task_type=snapshot.task_type,
            task_definition_version=snapshot.task_definition_version,
            task_definition_digest=snapshot.task_definition_digest,
            local_claim_credential_handle=credential_handle,
            journal=journal,
        )

    def wait_for_submission_status(
        self,
        task_id: str,
        submission_id: str,
        *,
        timeout_seconds: float = 300.0,
        max_attempts: int = 20,
    ) -> ScheduledRewardStatus:
        """Tokenless bounded polling with stable per-Submission jitter."""

        self._require_open()
        task = validate_task_id(task_id)
        submission = validate_submission_id(submission_id)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
            or type(max_attempts) is not int
            or not 1 <= max_attempts <= 100
        ):
            raise ValueError("Invalid status polling bound.")
        deadline = self._monotonic() + float(timeout_seconds)
        stable_jitter = int(hashlib.sha256(submission.encode("ascii")).hexdigest()[:8], 16)
        stable_jitter = (stable_jitter / float(0xFFFFFFFF)) * 0.25
        last: Optional[ScheduledRewardStatus] = None
        for attempt in range(max_attempts):
            last = self.get_submission_status(task, submission)
            if last.terminal:
                return last
            if attempt + 1 >= max_attempts:
                break
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                break
            requested = last.retry_after_seconds
            delay = (
                float(requested)
                if requested is not None
                else min(30.0, float(2 ** min(attempt, 5))) + stable_jitter
            )
            if delay >= remaining:
                break
            self._sleep(delay)
        if last is not None:
            return last
        raise TaskV2TransportError("TASK_V2_STATUS_UNAVAILABLE")

    def build_execution_context(
        self,
        credential: ScheduledTaskClaimCredential,
        readiness: ScheduledTaskReadiness,
        *,
        journal: TaskJournal,
    ) -> Any:
        """Verify the at-T digest already accepted by ``get_readiness``."""

        self._require_open()
        snapshot = _credential(credential)
        checked = ScheduledTaskReadiness.model_validate(readiness)
        if (
            checked.task_id != snapshot.task_id
            or checked.manifest_sha256 is None
            or checked.report_close_at != snapshot.report_close_at
            or checked._manifest_url_value() != snapshot._manifest_url_value()
        ):
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=False
            )
        credential_handle = snapshot.local_claim_credential_handle
        self._validate_journal_identity(journal, snapshot)
        journal_payload = journal.load().payload
        if (
            journal_payload["state"] == "INIT"
            or journal_payload["manifest_sha256"]
            != checked.manifest_sha256
        ):
            raise JournalError("JOURNAL_STATE_CONFLICT")
        expected_execution_id = derive_local_execution_id(
            snapshot.task_id, credential_handle
        )
        try:
            from .scheduled_http_get_batch import ScheduledExecutionContext

            context = ScheduledExecutionContext.from_credential_readiness(
                snapshot,
                checked,
            )
        except TaskV2Error:
            raise
        except Exception:
            raise TaskV2TransportError(
                "TASK_V2_EXECUTION_CONTEXT_INVALID", request_bytes_sent=False
            ) from None
        if (
            context.execution_id != expected_execution_id
            or context.task_type != snapshot.task_type
            or context.task_definition_version
            != snapshot.task_definition_version
            or context.task_definition_digest
            != snapshot.task_definition_digest
        ):
            raise TaskV2TransportError(
                "TASK_V2_EXECUTION_CONTEXT_INVALID", request_bytes_sent=False
            )
        return context


__all__ = ["AgentTaskV2Client"]
