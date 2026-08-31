"""Compose the v1.18 scheduled HTTP GET batch worker safely.

The CLI is the supported private-file entrypoint::

    ln-church-agent task run-scheduled-http-get-batch \
        --credential-file ./claims/TASK_ID.v2.json \
        --journal-file ./claims/TASK_ID.scheduled-journal.json

This library example starts after a trusted, model-external credential store
has reconstructed ``ScheduledTaskClaimCredential`` with its private-file
codec.  Call ``initialize_claim_journal`` once immediately after successful
Claim persistence; ``run_claimed_batch`` is deliberately load-only and never
repairs a missing journal.  Never pass a Claim token or signed Manifest URL
through argv, a model prompt, logs, or the journal.
"""

from pathlib import Path
from typing import Union

from ln_church_agent import (
    AgentTaskV2Client,
    ScheduledCompletionAcknowledgement,
    ScheduledHTTPGetBatchExecutor,
    ScheduledRewardStatus,
    ScheduledCompletionReport,
    ScheduledTaskClaimCredential,
    TaskJournal,
)


def _bound_journal(
    credential: ScheduledTaskClaimCredential,
    journal_path: Union[str, Path],
) -> TaskJournal:
    return TaskJournal(
        journal_path,
        task_id=credential.task_id,
        local_claim_credential_handle=(
            credential.local_claim_credential_handle
        ),
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )


def initialize_claim_journal(
    credential: ScheduledTaskClaimCredential,
    journal_path: Union[str, Path],
) -> TaskJournal:
    """Create the one definition-bound journal without making a request."""

    journal = _bound_journal(credential, journal_path)
    journal.create()
    return journal


def run_claimed_batch(
    credential: ScheduledTaskClaimCredential,
    journal_path: Union[str, Path],
) -> Union[ScheduledCompletionAcknowledgement, ScheduledRewardStatus]:
    """Run or resume one Claim without exposing either bearer value."""

    journal = _bound_journal(credential, journal_path)
    # Run/resume never repairs or recreates a lost journal.  Loading before
    # constructing the Venue client also makes the missing-journal boundary
    # visibly network-free.
    snapshot = journal.load()

    with AgentTaskV2Client() as client:
        state = snapshot.state
        if state in {"COMPOUND_COMPLETION_ACKED", "TERMINAL_STATUS"}:
            report = ScheduledCompletionReport.model_validate_json(
                journal.frozen_report_bytes(), strict=True
            )
            acknowledgement = client.recover_completion(
                credential, report, journal=journal
            )
            if (
                getattr(acknowledgement, "source", None) != "status"
                or getattr(acknowledgement, "status", None) is None
            ):
                raise RuntimeError("Submission status binding changed.")
            return acknowledgement.status
        if state == "REPORT_FROZEN":
            report = ScheduledCompletionReport.model_validate_json(
                journal.frozen_report_bytes()
            )
            return client.complete_task(
                credential, report, journal=journal
            )
        if state == "MANIFEST_FETCH_STARTED":
            frozen = client.recover_interrupted_manifest_fetch(
                credential, journal=journal
            )
            return client.complete_task(
                credential, frozen, journal=journal
            )
        if state not in {
            "INIT",
            "OFFER_RECHECKED",
            "MANIFEST_VERIFIED",
            "ATTEMPT_STARTED",
            "RESULT_RECORDED",
        }:
            raise RuntimeError("Unexpected scheduled journal state.")

        readiness = client.get_readiness(credential, journal=journal)
        context = client.build_execution_context(
            credential, readiness, journal=journal
        )
        frozen = ScheduledHTTPGetBatchExecutor().execute(
            context, journal=journal
        )
        return client.complete_task(
            credential, frozen, journal=journal
        )


__all__ = ["initialize_claim_journal", "run_claimed_batch"]
