"""v1.18 Scheduled HTTP GET Batch execution adapter.

The adapter consumes a post-T readiness result, fetches and validates the
server-pinned Manifest, performs one sequential GET per target, and freezes a
canonical compound Completion report.  Claim-token transport remains owned
by the parallel v2 client; this module never receives or serializes that
secret.  The signed Manifest URL is private in the execution context and is
used byte-for-byte for every release attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import time
from typing import Any, Callable, List, Mapping, Optional, Sequence, Tuple

from .network_fetch import (
    ControlledHTTPSConnector,
    FetchResponse,
    NetworkFetchError,
)
from .task_journal import (
    JournalError,
    TaskJournal,
    derive_local_execution_id as _derive_journal_execution_id,
)
from .task_v2_contract import (
    MANIFEST_FETCH_ATTEMPT_TOTAL_TIMEOUT_MS,
    MANIFEST_FETCH_MAXIMUM_ATTEMPTS,
    MANIFEST_FETCH_OPERATION_DEADLINE_MS,
    ManifestContractError,
    ValidatedManifest,
    parse_rfc3339_whole_second,
    validate_manifest_bytes,
    validate_opaque_id,
    validate_release_url,
    validate_sha256,
    validate_task_id,
)
from .task_v2_models import (
    ManifestFetchResult,
    ScheduledCompletionReport,
    ScheduledTargetResult,
    ScheduledTaskClaimCredential,
    ScheduledTaskReadiness,
)


class ScheduledExecutionError(Exception):
    """Finite adapter failure with no URL, token, or response data."""

    _CODES = frozenset(
        {
            "EXECUTION_CONTEXT_INVALID",
            "EXECUTION_UNAVAILABLE",
            "EXECUTION_JOURNAL_INVALID",
            "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS",
            "EXECUTION_REPORT_INVALID",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "EXECUTION_CONTEXT_INVALID"
        super().__init__(code)
        self.code = code


class _CanonicalHTTPSURL:
    """Private, non-serializable holder for one canonical wire URL.

    The signed query is deliberately not a dataclass field and is never put
    in an ordinary ``__dict__``.  Only the connector-facing accessor can
    recover the byte-exact value.
    """

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        validate_release_url(value)
        object.__setattr__(self, "_CanonicalHTTPSURL__value", value)

    def _transport_value(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "CanonicalHTTPSURL(REDACTED)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("CanonicalHTTPSURL is not serializable")


class ScheduledExecutionContext:
    """Immutable public execution facts plus a private signed wire URL."""

    __slots__ = (
        "task_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_sha256",
        "scheduled_at",
        "new_target_start_before",
        "report_close_at",
        "local_claim_credential_handle",
        "execution_id",
        "execution_available",
        "release_state",
        "__signed_manifest_url",
        "__sealed",
    )

    def __init__(
        self,
        *,
        task_id: str,
        task_type: str,
        task_definition_version: str,
        task_definition_digest: str,
        manifest_sha256: str,
        scheduled_at: str,
        new_target_start_before: str,
        report_close_at: str,
        local_claim_credential_handle: str,
        _signed_manifest_url: str,
        execution_available: bool = True,
        release_state: str = "READY",
    ) -> None:
        try:
            task_id = validate_task_id(task_id)
            if task_type != "scheduled_http_get_batch.v1":
                raise ValueError
            if task_definition_version != "1.0.0":
                raise ValueError
            task_definition_digest = validate_sha256(
                task_definition_digest, "task_definition_digest"
            )
            manifest_sha256 = validate_sha256(
                manifest_sha256, "manifest_sha256"
            )
            scheduled = parse_rfc3339_whole_second(scheduled_at, "scheduled_at")
            target_close = parse_rfc3339_whole_second(
                new_target_start_before, "new_target_start_before"
            )
            report_close = parse_rfc3339_whole_second(
                report_close_at, "report_close_at"
            )
            if (
                target_close != scheduled + timedelta(seconds=300)
                or report_close != scheduled + timedelta(seconds=600)
            ):
                raise ValueError
            validate_opaque_id(
                local_claim_credential_handle,
                "local_claim_credential_handle",
            )
            execution_id = derive_local_execution_id(
                task_id, local_claim_credential_handle
            )
            signed_manifest_url = _CanonicalHTTPSURL(_signed_manifest_url)
            if (
                type(execution_available) is not bool
                or release_state not in {"READY", "UNAVAILABLE"}
                or execution_available != (release_state == "READY")
            ):
                raise ValueError
            for name, value in (
                ("task_id", task_id),
                ("task_type", task_type),
                ("task_definition_version", task_definition_version),
                ("task_definition_digest", task_definition_digest),
                ("manifest_sha256", manifest_sha256),
                ("scheduled_at", scheduled_at),
                ("new_target_start_before", new_target_start_before),
                ("report_close_at", report_close_at),
                ("local_claim_credential_handle", local_claim_credential_handle),
                ("execution_id", execution_id),
                ("execution_available", execution_available),
                ("release_state", release_state),
                ("_ScheduledExecutionContext__signed_manifest_url", signed_manifest_url),
            ):
                object.__setattr__(self, name, value)
            object.__setattr__(self, "_ScheduledExecutionContext__sealed", True)
        except Exception:
            raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID") from None

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise AttributeError("ScheduledExecutionContext is immutable")

    @classmethod
    def from_credential_readiness(
        cls,
        credential: ScheduledTaskClaimCredential,
        readiness: ScheduledTaskReadiness,
    ) -> "ScheduledExecutionContext":
        try:
            credential = ScheduledTaskClaimCredential.model_validate(credential)
            readiness = ScheduledTaskReadiness.model_validate(readiness)
            if (
                readiness.release_state not in {"READY", "UNAVAILABLE"}
                or readiness.manifest_sha256 is None
                or readiness.new_target_start_before is None
                or readiness.report_close_at is None
            ):
                raise ScheduledExecutionError("EXECUTION_UNAVAILABLE")
            credential_url = credential._manifest_url_value()
            readiness_url = readiness._manifest_url_value()
            if (
                credential.task_id != readiness.task_id
                or credential.report_close_at != readiness.report_close_at
                or credential_url != readiness_url
            ):
                credential_url = None
                readiness_url = None
                raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID")
            return cls(
                task_id=credential.task_id,
                task_type=credential.task_type,
                task_definition_version=credential.task_definition_version,
                task_definition_digest=credential.task_definition_digest,
                manifest_sha256=readiness.manifest_sha256,
                scheduled_at=credential.scheduled_at,
                new_target_start_before=readiness.new_target_start_before,
                report_close_at=readiness.report_close_at,
                local_claim_credential_handle=credential._local_fingerprint(),
                _signed_manifest_url=readiness_url,
                execution_available=readiness.execution_available,
                release_state=readiness.release_state,
            )
        except ScheduledExecutionError:
            raise
        except Exception:
            raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID") from None

    def _manifest_url_value(self) -> str:
        return self.__signed_manifest_url._transport_value()

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return (
            "ScheduledExecutionContext(task_id=%r, execution_id=%r, "
            "signed_manifest_url=REDACTED)"
        ) % (self.task_id, self.execution_id)

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("ScheduledExecutionContext is not serializable")


def derive_local_execution_id(task_id: str, credential_handle: str) -> str:
    """Derive the stable, non-public execution binding used by the journal."""

    try:
        return _derive_journal_execution_id(task_id, credential_handle)
    except JournalError:
        raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID") from None


@dataclass(frozen=True)
class FrozenCompletionReport:
    report: ScheduledCompletionReport
    exact_bytes: bytes = field(repr=False)
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.exact_bytes) is not bytes
            or self.report.canonical_bytes() != self.exact_bytes
            or hashlib.sha256(self.exact_bytes).hexdigest() != self.sha256
        ):
            raise ScheduledExecutionError("EXECUTION_REPORT_INVALID")

    @property
    def submission_id(self) -> str:
        return self.report.submission_id

    def to_completion_report(self) -> ScheduledCompletionReport:
        return self.report


def _now_utc(value: Callable[[], datetime]) -> datetime:
    current = value()
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID")
    return current.astimezone(timezone.utc)


def _elapsed_ms(start: float, monotonic: Callable[[], float], maximum: int) -> int:
    return min(maximum, max(0, int(round((monotonic() - start) * 1000.0))))


def _manifest_network_outcome(code: str) -> str:
    return {
        "dns_error": "release_dns_error",
        "policy_rejected": "release_protocol_error",
        "tls_error": "release_tls_error",
        "connection_error": "release_connection_error",
        "timeout": "release_timeout",
        "protocol_error": "release_protocol_error",
        "response_too_large": "release_response_too_large",
        "encoding_unsupported": "release_encoding_unsupported",
    }.get(code, "release_protocol_error")


def _target_network_outcome(code: str) -> str:
    return {
        "dns_error": "dns_error",
        "policy_rejected": "protocol_error",
        "tls_error": "tls_error",
        "connection_error": "connection_error",
        "timeout": "timeout",
        "protocol_error": "protocol_error",
        "response_too_large": "protocol_error",
        "encoding_unsupported": "protocol_error",
    }.get(code, "protocol_error")


def _retryable_manifest_status(
    status: int, *, current: datetime, scheduled_at: datetime
) -> bool:
    if status in {429, 500, 502, 503, 504}:
        return True
    return status == 403 and scheduled_at <= current < scheduled_at + timedelta(seconds=2)


class ScheduledHTTPGetBatchExecutor:
    """Sequential, journaled official SDK executor."""

    def __init__(
        self,
        *,
        connector: Optional[ControlledHTTPSConnector] = None,
        monotonic: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.connector = connector or ControlledHTTPSConnector(monotonic=monotonic)
        self.monotonic = monotonic
        self.utcnow = utcnow

    @staticmethod
    def _verify_journal_binding(
        context: ScheduledExecutionContext, journal: TaskJournal
    ) -> None:
        try:
            journal.require_binding(
                task_id=context.task_id,
                local_claim_credential_handle=(
                    context.local_claim_credential_handle
                ),
                task_type=context.task_type,
                task_definition_version=context.task_definition_version,
                task_definition_digest=context.task_definition_digest,
            )
        except JournalError:
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        if context.execution_id != derive_local_execution_id(
            context.task_id, context.local_claim_credential_handle
        ) or journal.execution_id != context.execution_id:
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")

    def _freeze(
        self,
        context: ScheduledExecutionContext,
        journal: TaskJournal,
        manifest_fetch: ManifestFetchResult,
        results: Sequence[ScheduledTargetResult],
    ) -> FrozenCompletionReport:
        return self._freeze_bound_report(
            task_type=context.task_type,
            task_definition_version=context.task_definition_version,
            task_definition_digest=context.task_definition_digest,
            expected_manifest_sha256=context.manifest_sha256,
            journal=journal,
            manifest_fetch=manifest_fetch,
            results=results,
        )

    def _freeze_bound_report(
        self,
        *,
        task_type: str,
        task_definition_version: str,
        task_definition_digest: str,
        expected_manifest_sha256: str,
        journal: TaskJournal,
        manifest_fetch: ManifestFetchResult,
        results: Sequence[ScheduledTargetResult],
    ) -> FrozenCompletionReport:
        try:
            bound_manifest_sha256 = journal.load().payload["manifest_sha256"]
        except JournalError as error:
            if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                raise ScheduledExecutionError(
                    "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                ) from None
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
        if (
            type(bound_manifest_sha256) is not str
            or bound_manifest_sha256 != expected_manifest_sha256
        ):
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        report = ScheduledCompletionReport(
            submission_id="sub_" + secrets.token_hex(16),
            task_type=task_type,
            task_definition_version=task_definition_version,
            task_definition_digest=task_definition_digest,
            manifest_sha256=bound_manifest_sha256,
            manifest_fetch=manifest_fetch,
            results=list(results),
            completed_at=_now_utc(self.utcnow).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        exact = report.canonical_bytes()
        try:
            journal.freeze_report(
                exact,
                submission_id=report.submission_id,
                manifest_fetch_outcome=manifest_fetch.outcome,
            )
        except JournalError as error:
            if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                raise ScheduledExecutionError(
                    "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                ) from None
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
        return FrozenCompletionReport(
            report=report,
            exact_bytes=exact,
            sha256=hashlib.sha256(exact).hexdigest(),
        )

    def recover_interrupted_manifest_fetch(
        self,
        *,
        task_id: str,
        task_type: str,
        task_definition_version: str,
        task_definition_digest: str,
        local_claim_credential_handle: str,
        journal: TaskJournal,
    ) -> FrozenCompletionReport:
        """Freeze the official no-I/O report for an interrupted Manifest fetch.

        This entrypoint intentionally accepts no readiness object and no
        release URL.  Its only Manifest authority is the digest already bound
        in the durable journal before the interrupted request began.
        """

        try:
            validate_task_id(task_id)
            if task_type != "scheduled_http_get_batch.v1":
                raise ValueError
            if task_definition_version != "1.0.0":
                raise ValueError
            validate_sha256(task_definition_digest, "task_definition_digest")
            validate_opaque_id(
                local_claim_credential_handle,
                "local_claim_credential_handle",
            )
            execution_id = derive_local_execution_id(
                task_id, local_claim_credential_handle
            )
        except Exception:
            raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID") from None
        if not isinstance(journal, TaskJournal):
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        try:
            journal.require_binding(
                task_id=task_id,
                local_claim_credential_handle=local_claim_credential_handle,
                task_type=task_type,
                task_definition_version=task_definition_version,
                task_definition_digest=task_definition_digest,
            )
        except JournalError:
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
        if journal.execution_id != execution_id:
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        try:
            snapshot = journal.load()
        except JournalError as error:
            if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                raise ScheduledExecutionError(
                    "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                ) from None
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
        bound_manifest_sha256 = snapshot.payload["manifest_sha256"]
        if (
            snapshot.state != "MANIFEST_FETCH_STARTED"
            or type(bound_manifest_sha256) is not str
        ):
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        return self._freeze_bound_report(
            task_type=task_type,
            task_definition_version=task_definition_version,
            task_definition_digest=task_definition_digest,
            expected_manifest_sha256=bound_manifest_sha256,
            journal=journal,
            manifest_fetch=ManifestFetchResult(outcome="release_interrupted"),
            results=[],
        )

    def _frozen_from_journal(self, journal: TaskJournal) -> FrozenCompletionReport:
        try:
            exact = journal.frozen_report_bytes()
            report = ScheduledCompletionReport.model_validate_json(exact)
            return FrozenCompletionReport(
                report=report,
                exact_bytes=exact,
                sha256=hashlib.sha256(exact).hexdigest(),
            )
        except Exception:
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None

    def _fetch_manifest(
        self,
        context: ScheduledExecutionContext,
        journal: TaskJournal,
    ) -> Tuple[ManifestFetchResult, Optional[ValidatedManifest]]:
        operation_start = self.monotonic()
        operation_deadline = (
            operation_start + MANIFEST_FETCH_OPERATION_DEADLINE_MS / 1000.0
        )
        scheduled_at = parse_rfc3339_whole_second(context.scheduled_at, "scheduled_at")
        report_close = parse_rfc3339_whole_second(
            context.report_close_at, "report_close_at"
        )
        final_outcome = "release_timeout"
        final_status: Optional[int] = None
        final_observed: Optional[str] = None
        signed_url = context._manifest_url_value()
        try:
            for attempt in range(MANIFEST_FETCH_MAXIMUM_ATTEMPTS):
                if (
                    operation_deadline - self.monotonic()
                    < MANIFEST_FETCH_ATTEMPT_TOTAL_TIMEOUT_MS / 1000.0
                    or _now_utc(self.utcnow) >= report_close
                ):
                    break
                try:
                    journal.start_manifest_attempt()
                except JournalError as error:
                    if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                        raise ScheduledExecutionError(
                            "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                        ) from None
                    raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
                try:
                    response = self.connector.fetch_manifest(signed_url)
                except NetworkFetchError as error:
                    final_outcome = _manifest_network_outcome(error.code)
                    retryable = error.code in {"dns_error", "connection_error", "timeout"}
                    if retryable and attempt + 1 < MANIFEST_FETCH_MAXIMUM_ATTEMPTS:
                        continue
                    break
                if response.status_code != 200:
                    final_outcome = "release_http_unexpected_status"
                    final_status = response.status_code
                    if (
                        _retryable_manifest_status(
                            response.status_code,
                            current=_now_utc(self.utcnow),
                            scheduled_at=scheduled_at,
                        )
                        and attempt + 1 < MANIFEST_FETCH_MAXIMUM_ATTEMPTS
                    ):
                        continue
                    break
                observed = hashlib.sha256(response.body).hexdigest()
                try:
                    manifest = validate_manifest_bytes(
                        response.body, context.manifest_sha256
                    )
                except ManifestContractError as error:
                    final_outcome = error.outcome
                    if error.outcome == "release_digest_mismatch":
                        final_status = 200
                        final_observed = observed
                    break
                if not context.execution_available:
                    # Readiness UNAVAILABLE is authoritative.  The signed URL
                    # may be fetched to obtain a typed release outcome, but a
                    # surprising valid body must never unlock target access.
                    final_outcome = "release_protocol_error"
                    break
                try:
                    journal.bind_verified_manifest(
                        context.manifest_sha256,
                        len(manifest.urls),
                        manifest_bytes=manifest.raw_bytes,
                    )
                except JournalError as error:
                    if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                        raise ScheduledExecutionError(
                            "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                        ) from None
                    raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
                return (
                    ManifestFetchResult(
                        outcome="retrieved",
                        observed_sha256=observed,
                        http_status=200,
                        elapsed_ms=_elapsed_ms(operation_start, self.monotonic, 5000),
                    ),
                    manifest,
                )
        finally:
            signed_url = None
        fields: dict = {
            "outcome": final_outcome,
            "elapsed_ms": _elapsed_ms(operation_start, self.monotonic, 5000),
        }
        if final_outcome == "release_http_unexpected_status":
            fields["http_status"] = final_status
        elif final_outcome == "release_digest_mismatch":
            fields["http_status"] = 200
            fields["observed_sha256"] = final_observed
        return ManifestFetchResult(**fields), None

    def _journal_results(
        self, manifest: ValidatedManifest, payload: Mapping[str, Any]
    ) -> List[ScheduledTargetResult]:
        results: List[ScheduledTargetResult] = []
        for item in payload["targets"]:
            if item["state"] != "RESULT_RECORDED":
                break
            fields = {
                "position": item["position"],
                "target_url": manifest.urls[item["position"]],
                "outcome": item["outcome"],
            }
            if "http_status" in item:
                fields["http_status"] = item["http_status"]
            if "elapsed_ms" in item:
                fields["elapsed_ms"] = item["elapsed_ms"]
            results.append(ScheduledTargetResult(**fields))
        return results

    def _execute_targets(
        self,
        context: ScheduledExecutionContext,
        journal: TaskJournal,
        manifest: ValidatedManifest,
    ) -> List[ScheduledTargetResult]:
        cutoff = parse_rfc3339_whole_second(
            context.new_target_start_before, "new_target_start_before"
        )
        payload = journal.load().payload
        if payload["state"] == "ATTEMPT_STARTED":
            interrupted = next(
                item for item in payload["targets"] if item["state"] == "ATTEMPT_STARTED"
            )
            journal.record_target_result(
                interrupted["position"], "interrupted_indeterminate"
            )
            payload = journal.load().payload
        results = self._journal_results(manifest, payload)
        for position in range(len(results), len(manifest.urls)):
            target_url = manifest.urls[position]
            if _now_utc(self.utcnow) >= cutoff:
                journal.record_target_result(position, "not_attempted_deadline")
                results.append(
                    ScheduledTargetResult(
                        position=position,
                        target_url=target_url,
                        outcome="not_attempted_deadline",
                    )
                )
                continue
            try:
                journal.mark_target_attempt_started(position)
            except JournalError as error:
                if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                    raise ScheduledExecutionError(
                        "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                    ) from None
                raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
            started = self.monotonic()
            try:
                response = self.connector.fetch_target(target_url)
                outcome = "http_response"
                status = response.status_code
            except NetworkFetchError as error:
                outcome = _target_network_outcome(error.code)
                status = None
            elapsed = _elapsed_ms(started, self.monotonic, 12000)
            try:
                journal.record_target_result(
                    position,
                    outcome,
                    http_status=status,
                    elapsed_ms=elapsed,
                )
            except JournalError as error:
                if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                    raise ScheduledExecutionError(
                        "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                    ) from None
                raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
            fields = {
                "position": position,
                "target_url": target_url,
                "outcome": outcome,
                "elapsed_ms": elapsed,
            }
            if status is not None:
                fields["http_status"] = status
            results.append(ScheduledTargetResult(**fields))
        return results

    def execute(
        self,
        context: ScheduledExecutionContext,
        *,
        journal: TaskJournal,
    ) -> FrozenCompletionReport:
        if not isinstance(context, ScheduledExecutionContext) or not isinstance(
            journal, TaskJournal
        ):
            raise ScheduledExecutionError("EXECUTION_CONTEXT_INVALID")
        self._verify_journal_binding(context, journal)
        try:
            snapshot = journal.load()
        except JournalError as error:
            if error.code == "JOURNAL_PERSISTENCE_AMBIGUOUS":
                raise ScheduledExecutionError(
                    "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
                ) from None
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
        if snapshot.state == "INIT":
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        if (
            type(snapshot.payload["manifest_sha256"]) is not str
            or snapshot.payload["manifest_sha256"]
            != context.manifest_sha256
        ):
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        if snapshot.state in {
            "REPORT_FROZEN",
            "COMPOUND_COMPLETION_ACKED",
            "TERMINAL_STATUS",
        }:
            return self._frozen_from_journal(journal)
        if snapshot.state == "MANIFEST_FETCH_STARTED":
            manifest_fetch = ManifestFetchResult(outcome="release_interrupted")
            return self._freeze(context, journal, manifest_fetch, [])
        if snapshot.state == "OFFER_RECHECKED":
            manifest_fetch, manifest = self._fetch_manifest(context, journal)
            if manifest is None:
                return self._freeze(context, journal, manifest_fetch, [])
        elif snapshot.state in {"MANIFEST_VERIFIED", "ATTEMPT_STARTED", "RESULT_RECORDED"}:
            try:
                manifest = validate_manifest_bytes(
                    journal.verified_manifest_bytes(), context.manifest_sha256
                )
            except Exception:
                raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID") from None
            manifest_fetch = ManifestFetchResult(
                outcome="retrieved",
                observed_sha256=context.manifest_sha256,
                http_status=200,
            )
        else:
            raise ScheduledExecutionError("EXECUTION_JOURNAL_INVALID")
        results = self._execute_targets(context, journal, manifest)
        return self._freeze(context, journal, manifest_fetch, results)


# Readable spelling used in documentation while retaining the acronym form.
ScheduledHttpGetBatchExecutor = ScheduledHTTPGetBatchExecutor


__all__ = [
    "FrozenCompletionReport",
    "ScheduledExecutionContext",
    "ScheduledExecutionError",
    "ScheduledHTTPGetBatchExecutor",
    "ScheduledHttpGetBatchExecutor",
    "derive_local_execution_id",
]
