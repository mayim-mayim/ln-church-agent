"""One Claim, one selected endpoint, one durable report; no target payment."""

from __future__ import annotations

from datetime import datetime, timezone
import secrets
from typing import Any

from .immediate_visit_journal import ImmediateVisitJournal
from .immediate_visit_models import FrozenImmediateVisitReport, ImmediateVisitClaimCredential
from .immediate_visit_profile import analyze_response
from .network_fetch import ImmediateVisitFetchError, fetch_immediate_visit_once
from .task_journal import JournalError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ImmediateVisitExecutor:
    """Execute one selected Claim endpoint and freeze the report before return.

    All executors for a Claim must share the same private journal directory.
    Reopening a started Claim never retries its target GET. Caller-controlled
    fetch/profile overrides are intentionally absent.
    """

    def __init__(self, *, journal: ImmediateVisitJournal) -> None:
        if not isinstance(journal, ImmediateVisitJournal):
            raise JournalError("JOURNAL_INVALID")
        self.journal = journal

    def __repr__(self) -> str:
        return "ImmediateVisitExecutor(<private>)"

    def execute(self, claim: ImmediateVisitClaimCredential,
                endpoint_id: str) -> FrozenImmediateVisitReport:
        snapshot = ImmediateVisitClaimCredential.model_validate(claim)
        self.journal.require_binding(snapshot)
        endpoint = next((item for item in snapshot.endpoints if item.endpoint_id == endpoint_id), None)
        if endpoint is None:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        with self.journal.fetch_operation_guard():
            frozen = self.journal.load_report(snapshot)
            if frozen is not None:
                if frozen.endpoint_id != endpoint_id:
                    raise JournalError("JOURNAL_STATE_CONFLICT")
                return frozen
            start = self.journal.begin_fetch(snapshot, endpoint_id, _now())
            if not start["start_permitted"]:
                # The stable operation lock proves no cooperative executor is
                # still acquiring this Claim. A prior process lost its result.
                observation = dict(outcome="inconclusive", reason="fetch_outcome_lost",
                                   status=None, media_family=None, body_bytes=None)
            else:
                observation = self._fetch(endpoint.url)
            observation["fetch_started_at"] = start["fetch_started_at"]
            observation["fetch_finished_at"] = _now()
            frozen = FrozenImmediateVisitReport.from_report({
                "schema_version": "ln_church.task_completion.immediate_visit.v1",
                "task_id": snapshot.task_id,
                "execution_id": snapshot.execution_id,
                "submission_id": "sub_" + secrets.token_hex(16),
                "endpoint_id": endpoint_id,
                "profile_id": snapshot.profile_id,
                "observation": observation,
            })
            self.journal.save_observation(snapshot, frozen)
            return frozen

    @staticmethod
    def _fetch(url: str) -> Any:
        response = None
        try:
            response = fetch_immediate_visit_once(url)
            return analyze_response(response.status_code, response.headers, response.body)
        except ImmediateVisitFetchError as error:
            return dict(outcome="inconclusive", reason=error.reason,
                        status=error.status_code, media_family=None, body_bytes=error.body_bytes)
        finally:
            # No response body, headers or extracted text enter persistent state.
            response = None


__all__ = ["ImmediateVisitExecutor", "FrozenImmediateVisitReport"]
