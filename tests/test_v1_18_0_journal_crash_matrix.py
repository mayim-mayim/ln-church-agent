import hashlib
import os
import subprocess
import sys
import textwrap

import pytest

from ln_church_agent.task_contract import jcs_canonical_bytes
from ln_church_agent.task_journal import JournalError, TaskJournal


TASK_ID = "task_crash_matrix"
HANDLE = "cred_" + "d" * 64
DEFINITION_DIGEST = "a" * 64
SUBMISSION_ID = "sub_" + "f" * 32
MANIFEST = jcs_canonical_bytes(
    {
        "schema_version": "ln_church.http_get_batch_manifest.v1",
        "method": "GET",
        "urls": ["https://example.com/a"],
    }
)
MANIFEST_DIGEST = hashlib.sha256(MANIFEST).hexdigest()


def _report():
    return jcs_canonical_bytes(
        {
            "schema_version": "ln_church.scheduled_http_get_batch_completion.v1",
            "submission_id": SUBMISSION_ID,
            "task_type": "scheduled_http_get_batch.v1",
            "task_definition_version": "1.0.0",
            "task_definition_digest": DEFINITION_DIGEST,
            "manifest_sha256": MANIFEST_DIGEST,
            "manifest_fetch": {
                "outcome": "retrieved",
                "observed_sha256": MANIFEST_DIGEST,
                "http_status": 200,
            },
            "results": [
                {
                    "position": 0,
                    "target_url": "https://example.com/a",
                    "outcome": "interrupted_indeterminate",
                }
            ],
            "completed_at": "2026-08-20T03:04:40Z",
        }
    )


def _acknowledgement():
    return {
        "source": "receipt",
        "task_id": TASK_ID,
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DEFINITION_DIGEST,
        "manifest_sha256": MANIFEST_DIGEST,
        "submission_id": SUBMISSION_ID,
        "report_id": "report_1",
        "report_sha256": hashlib.sha256(_report()).hexdigest(),
        "completion_id": "completion_1",
        "accepted_at": "2026-08-20T03:04:42Z",
        "receipt_state": "DURABLY_ACCEPTED",
    }


def _terminal_status():
    return {
        "schema_version": "ln_church.agent_task_reward_status.v2",
        "task_id": TASK_ID,
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DEFINITION_DIGEST,
        "manifest_sha256": MANIFEST_DIGEST,
        "submission_id": SUBMISSION_ID,
        "report_id": "report_1",
        "report_sha256": hashlib.sha256(_report()).hexdigest(),
        "accepted_at": "2026-08-20T03:04:42Z",
        "receipt_state": "DURABLY_ACCEPTED",
        "evaluation": {"state": "APPROVED", "reason": "EVALUATED"},
        "base_reward": {
            "entitlement_state": "TERMINAL",
            "settlement_state": "PAID_CONFIRMED",
        },
        "reference_bonus": {
            "candidate": False,
            "decision_state": "NOT_AWARDED",
        },
        "terminal": True,
        "retry_after_seconds": 0,
    }


def _journal(path):
    return TaskJournal(
        path,
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
    )


def _advance_to_frozen(journal):
    journal.create()
    journal.mark_offer_rechecked(MANIFEST_DIGEST)
    journal.start_manifest_attempt()
    journal.bind_verified_manifest(
        MANIFEST_DIGEST, 1, manifest_bytes=MANIFEST
    )
    journal.mark_target_attempt_started(0)
    journal.record_target_result(0, "interrupted_indeterminate")
    journal.freeze_report(
        _report(),
        submission_id=SUBMISSION_ID,
        manifest_fetch_outcome="retrieved",
    )


@pytest.mark.parametrize("lost_at", ["INIT", "ATTEMPT_STARTED", "REPORT_FROZEN"])
def test_lost_journal_never_recreates_from_any_irreversible_checkpoint(
    lost_at, tmp_path
):
    path = tmp_path / ("lost-" + lost_at + ".journal")
    journal = _journal(path)
    journal.create()
    if lost_at != "INIT":
        journal.mark_offer_rechecked(MANIFEST_DIGEST)
        journal.start_manifest_attempt()
        journal.bind_verified_manifest(
            MANIFEST_DIGEST, 1, manifest_bytes=MANIFEST
        )
        journal.mark_target_attempt_started(0)
    if lost_at == "REPORT_FROZEN":
        journal.record_target_result(0, "interrupted_indeterminate")
        journal.freeze_report(
            _report(),
            submission_id=SUBMISSION_ID,
            manifest_fetch_outcome="retrieved",
        )
    assert journal.load().state == lost_at
    path.unlink()

    with pytest.raises(JournalError, match="^JOURNAL_MISSING$"):
        journal.load()
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX subprocess crash evidence")
@pytest.mark.parametrize(
    "stage",
    [
        "before_temp_write",
        "after_temp_write",
        "after_file_fsync",
        "before_replace",
        "after_replace",
        "after_directory_fsync",
    ],
)
def test_real_process_exit_during_atomic_update_leaves_old_or_new_valid(stage, tmp_path):
    path = tmp_path / "crash.journal"
    _journal(path).create()
    script = textwrap.dedent(
        """
        import os
        import sys
        from ln_church_agent.task_journal import TaskJournal

        path, stage = sys.argv[1:]
        def crash(current):
            if current == stage:
                os._exit(73)
        journal = TaskJournal(
            path,
            task_id=%r,
            local_claim_credential_handle=%r,
            task_type="scheduled_http_get_batch.v1",
            task_definition_version="1.0.0",
            task_definition_digest=%r,
            fault_hook=crash,
        )
        journal.mark_offer_rechecked(%r)
        """
        % (TASK_ID, HANDLE, DEFINITION_DIGEST, MANIFEST_DIGEST)
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(path), stage],
        check=False,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    assert result.returncode == 73
    snapshot = _journal(path).load()
    assert snapshot.state in {"INIT", "OFFER_RECHECKED"}
    if snapshot.state == "INIT":
        assert snapshot.payload["manifest_sha256"] is None
    else:
        assert snapshot.payload["manifest_sha256"] == MANIFEST_DIGEST
    leftovers = list(tmp_path.glob(".crash.journal.*.tmp"))
    # A crash can leave an unreferenced temporary file.  It is never selected
    # as journal state and subsequent locked recovery remains fail-closed.
    assert all(item.name != path.name for item in leftovers)


@pytest.mark.parametrize(
    ("checkpoint", "expected_state", "expected_disposition"),
    [
        ("MANIFEST_FETCH_STARTED", "MANIFEST_FETCH_STARTED", "release_interrupted"),
        ("ATTEMPT_STARTED", "ATTEMPT_STARTED", "target_interrupted_indeterminate"),
        ("REPORT_FROZEN", "REPORT_FROZEN", "completion_dispatch"),
        (
            "REPORT_FROZEN_DISPATCH_ATTEMPTED",
            "REPORT_FROZEN",
            "completion_status_first",
        ),
        ("COMPOUND_COMPLETION_ACKED", "COMPOUND_COMPLETION_ACKED", "status_only"),
    ],
)
def test_restart_disposition_is_fail_closed_at_irreversible_boundaries(
    checkpoint, expected_state, expected_disposition, tmp_path
):
    # State-specific construction uses the real journal methods so the test
    # also fixes the durable transition order.
    path = tmp_path / (checkpoint + ".journal")
    journal = _journal(path)
    journal.create()
    journal.mark_offer_rechecked(MANIFEST_DIGEST)
    journal.start_manifest_attempt()
    if checkpoint != "MANIFEST_FETCH_STARTED":
        journal.bind_verified_manifest(
            MANIFEST_DIGEST, 1, manifest_bytes=MANIFEST
        )
        journal.mark_target_attempt_started(0)
    if checkpoint in {
        "REPORT_FROZEN",
        "REPORT_FROZEN_DISPATCH_ATTEMPTED",
        "COMPOUND_COMPLETION_ACKED",
    }:
        journal.record_target_result(0, "interrupted_indeterminate")
        journal.freeze_report(
            _report(),
            submission_id=SUBMISSION_ID,
            manifest_fetch_outcome="retrieved",
        )
        if checkpoint != "REPORT_FROZEN":
            journal.mark_completion_dispatch_attempted()
        if checkpoint == "COMPOUND_COMPLETION_ACKED":
            journal.mark_compound_completion_acked(_acknowledgement())
    assert journal.load().state == expected_state
    assert journal.load().payload["manifest_sha256"] == MANIFEST_DIGEST
    assert journal.resume_disposition() == expected_disposition


@pytest.mark.skipif(os.name == "nt", reason="POSIX subprocess crash evidence")
@pytest.mark.parametrize("operation", ["dispatch", "ack", "terminal"])
@pytest.mark.parametrize(
    "stage",
    [
        "before_temp_write",
        "after_temp_write",
        "after_file_fsync",
        "before_replace",
        "after_replace",
        "after_directory_fsync",
    ],
)
def test_real_process_exit_during_dispatch_or_atomic_ack_is_old_or_new_valid(
    operation, stage, tmp_path
):
    path = tmp_path / (operation + ".journal")
    journal = _journal(path)
    _advance_to_frozen(journal)
    if operation in {"ack", "terminal"}:
        journal.mark_completion_dispatch_attempted()
    if operation == "terminal":
        journal.mark_compound_completion_acked(_acknowledgement())
    script = textwrap.dedent(
        """
        import os
        import sys
        from ln_church_agent.task_journal import TaskJournal

        path, operation, stage = sys.argv[1:]
        def crash(current):
            if current == stage:
                os._exit(74)
        journal = TaskJournal(
            path,
            task_id=%r,
            local_claim_credential_handle=%r,
            task_type="scheduled_http_get_batch.v1",
            task_definition_version="1.0.0",
            task_definition_digest=%r,
            fault_hook=crash,
        )
        if operation == "dispatch":
            journal.mark_completion_dispatch_attempted()
        elif operation == "ack":
            journal.mark_compound_completion_acked(%r)
        else:
            journal.mark_terminal_status(%r)
        """
        % (
            TASK_ID,
            HANDLE,
            DEFINITION_DIGEST,
            _acknowledgement(),
            _terminal_status(),
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(path), operation, stage],
        check=False,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    assert result.returncode == 74
    recovered = _journal(path)
    snapshot = recovered.load()
    if operation == "dispatch":
        assert snapshot.state == "REPORT_FROZEN"
        assert snapshot.payload["completion_dispatch_attempts"] in {0, 1}
    elif operation == "ack":
        assert snapshot.state in {"REPORT_FROZEN", "COMPOUND_COMPLETION_ACKED"}
        if snapshot.state == "COMPOUND_COMPLETION_ACKED":
            assert recovered.compound_acknowledgement_facts()["completion_id"] == (
                "completion_1"
            )
    else:
        assert snapshot.state in {"COMPOUND_COMPLETION_ACKED", "TERMINAL_STATUS"}
        if snapshot.state == "TERMINAL_STATUS":
            assert snapshot.payload["terminal_status"]["terminal"] is True
