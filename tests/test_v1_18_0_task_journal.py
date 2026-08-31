import hashlib
import json
import os
import stat

import pytest

from ln_church_agent.task_contract import jcs_canonical_bytes
from ln_church_agent.task_journal import (
    JOURNAL_CHECKSUM_DOMAIN,
    JOURNAL_SCHEMA_VERSION,
    JournalError,
    JournalPersistenceError,
    TaskJournal,
    derive_local_execution_id,
)
from ln_church_agent.task_v2_models import (
    ScheduledCompletionAcknowledgement,
    ScheduledRewardStatus,
)


TASK_ID = "task_v18_journal"
HANDLE = "cred_" + "a" * 64
MANIFEST = jcs_canonical_bytes(
    {
        "schema_version": "ln_church.http_get_batch_manifest.v1",
        "method": "GET",
        "urls": ["https://example.com/a", "https://example.com/b"],
    }
)
DIGEST = hashlib.sha256(MANIFEST).hexdigest()
DEFINITION_DIGEST = "9" * 64
SUBMISSION_ID = "sub_" + "c" * 32


def _report():
    return jcs_canonical_bytes(
        {
            "schema_version": "ln_church.scheduled_http_get_batch_completion.v1",
            "submission_id": SUBMISSION_ID,
            "task_type": "scheduled_http_get_batch.v1",
            "task_definition_version": "1.0.0",
            "task_definition_digest": DEFINITION_DIGEST,
            "manifest_sha256": DIGEST,
            "manifest_fetch": {
                "outcome": "retrieved",
                "observed_sha256": DIGEST,
                "http_status": 200,
                "elapsed_ms": 2,
            },
            "results": [
                {
                    "position": 0,
                    "target_url": "https://example.com/a",
                    "outcome": "http_response",
                    "http_status": 200,
                    "elapsed_ms": 1,
                },
                {
                    "position": 1,
                    "target_url": "https://example.com/b",
                    "outcome": "timeout",
                    "elapsed_ms": 2,
                },
            ],
            "completed_at": "2026-08-20T03:04:40Z",
        }
    )


def _failure_report(outcome="release_timeout"):
    return jcs_canonical_bytes(
        {
            "schema_version": "ln_church.scheduled_http_get_batch_completion.v1",
            "submission_id": SUBMISSION_ID,
            "task_type": "scheduled_http_get_batch.v1",
            "task_definition_version": "1.0.0",
            "task_definition_digest": DEFINITION_DIGEST,
            "manifest_sha256": DIGEST,
            "manifest_fetch": {
                "outcome": outcome,
                "elapsed_ms": 2,
            },
            "results": [],
            "completed_at": "2026-08-20T03:04:40Z",
        }
    )


def _acknowledgement(source="receipt", **changes):
    report = _report()
    facts = {
        "task_id": TASK_ID,
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DEFINITION_DIGEST,
        "manifest_sha256": DIGEST,
        "submission_id": SUBMISSION_ID,
        "report_id": "report_1",
        "report_sha256": hashlib.sha256(report).hexdigest(),
        "accepted_at": "2026-08-20T03:04:42Z",
        "receipt_state": "DURABLY_ACCEPTED",
    }
    if source == "receipt":
        facts.update(
            {
                "schema_version": "ln_church.agent_task_completion_receipt.v2",
                "completion_id": "completion_1",
                "evaluation_state": "PENDING",
            }
        )
    else:
        facts.update(
            {
                "schema_version": "ln_church.agent_task_reward_status.v2",
                "evaluation": {
                    "state": "PENDING",
                    "reason": "STRUCTURALLY_VALID",
                },
                "base_reward": {
                    "entitlement_state": "DUE",
                    "settlement_state": "CONFIRMING",
                },
                "reference_bonus": {
                    "candidate": True,
                    "decision_state": "PENDING",
                },
                "terminal": False,
                "retry_after_seconds": 15,
            }
        )
    facts.update(changes)
    return {"source": source, source: facts}


def _terminal_status(**changes):
    status = _acknowledgement("status")["status"]
    status["evaluation"] = {
        "state": "APPROVED",
        "reason": "STRUCTURALLY_VALID",
    }
    status["base_reward"] = {
        "entitlement_state": "TERMINAL",
        "settlement_state": "PAID_CONFIRMED",
    }
    status["reference_bonus"] = {
        "candidate": True,
        "decision_state": "AWARDED",
        "settlement_state": "PAID_CONFIRMED",
    }
    status["terminal"] = True
    status["retry_after_seconds"] = 0
    status.update(changes)
    return status


def _journal(tmp_path, **kwargs):
    return TaskJournal(
        tmp_path / "run.journal",
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
        **kwargs,
    )


def _freeze_retrieved_report(journal):
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()
    journal.bind_verified_manifest(DIGEST, 2, manifest_bytes=MANIFEST)
    journal.mark_target_attempt_started(0)
    journal.record_target_result(0, "http_response", http_status=200, elapsed_ms=1)
    journal.mark_target_attempt_started(1)
    journal.record_target_result(1, "timeout", elapsed_ms=2)
    report = _report()
    journal.freeze_report(
        report,
        submission_id=SUBMISSION_ID,
        manifest_fetch_outcome="retrieved",
    )
    return report


def test_explicit_journal_create_is_versioned_checksummed_and_private(tmp_path):
    journal = _journal(tmp_path)
    snapshot = journal.create()
    assert snapshot.state == "INIT"
    envelope = json.loads(journal.path.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == JOURNAL_SCHEMA_VERSION
    assert len(envelope["checksum"]) == 64
    assert envelope["payload"]["task_id"] == TASK_ID
    assert envelope["payload"]["local_claim_credential_handle"] == HANDLE
    assert envelope["payload"]["task_type"] == "scheduled_http_get_batch.v1"
    assert envelope["payload"]["task_definition_version"] == "1.0.0"
    assert envelope["payload"]["task_definition_digest"] == DEFINITION_DIGEST
    assert envelope["payload"]["execution_id"] == derive_local_execution_id(
        TASK_ID, HANDLE
    )
    assert journal.execution_id == envelope["payload"]["execution_id"]
    if os.name != "nt":
        assert stat.S_IMODE(journal.path.stat().st_mode) == 0o600
        assert stat.S_IMODE(journal.lock_path.stat().st_mode) == 0o600


def test_missing_corrupt_and_wrong_binding_fail_closed(tmp_path):
    journal = _journal(tmp_path)
    with pytest.raises(JournalError, match="^JOURNAL_MISSING$"):
        journal.load()
    journal.create()
    envelope = json.loads(journal.path.read_text(encoding="utf-8"))
    envelope["checksum"] = "0" * 64
    journal.path.write_text(json.dumps(envelope), encoding="utf-8")
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.load()
    other = TaskJournal(
        journal.path,
        task_id="other",
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
    )
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        other.load()


def test_definition_binding_is_required_and_mismatch_fails_before_journal_io(
    tmp_path, monkeypatch
):
    journal = _journal(tmp_path)
    journal.create()

    def forbidden_open(*_args, **_kwargs):
        raise AssertionError("journal I/O occurred")

    with monkeypatch.context() as isolated:
        isolated.setattr(os, "open", forbidden_open)
        with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
            journal.require_binding(
                task_id=TASK_ID,
                local_claim_credential_handle=HANDLE,
                task_type="scheduled_http_get_batch.v1",
                task_definition_version="1.0.0",
                task_definition_digest="8" * 64,
            )
    assert journal.load().payload["task_definition_digest"] == DEFINITION_DIGEST

    rebound = TaskJournal(
        journal.path,
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest="8" * 64,
    )
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        rebound.load()


def test_constructor_has_no_caller_execution_id_authority(tmp_path):
    with pytest.raises(TypeError):
        TaskJournal(
            tmp_path / "invalid.journal",
            task_id=TASK_ID,
            local_claim_credential_handle=HANDLE,
            task_type="scheduled_http_get_batch.v1",
            task_definition_version="1.0.0",
            task_definition_digest=DEFINITION_DIGEST,
            execution_id="exec_" + "0" * 32,
        )


def test_old_draft_without_definition_binding_and_forged_execution_fail_closed(
    tmp_path,
):
    journal = _journal(tmp_path)
    journal.create()
    original = journal.path.read_bytes()
    envelope = json.loads(original.decode("utf-8"))
    for field in (
        "task_type",
        "task_definition_version",
        "task_definition_digest",
    ):
        envelope["payload"].pop(field)
    envelope["checksum"] = hashlib.sha256(
        JOURNAL_CHECKSUM_DOMAIN + jcs_canonical_bytes(envelope["payload"])
    ).hexdigest()
    journal.path.write_bytes(jcs_canonical_bytes(envelope) + b"\n")
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.load()

    journal.path.write_bytes(original)
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    envelope = json.loads(original.decode("utf-8"))
    envelope["payload"]["execution_id"] = "exec_" + "0" * 32
    envelope["checksum"] = hashlib.sha256(
        JOURNAL_CHECKSUM_DOMAIN + jcs_canonical_bytes(envelope["payload"])
    ).hexdigest()
    journal.path.write_bytes(jcs_canonical_bytes(envelope) + b"\n")
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.load()


def test_manifest_binding_is_irreversible_and_attempt_budget_is_three(tmp_path):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    for _ in range(3):
        journal.start_manifest_attempt()
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        journal.start_manifest_attempt()
    journal.bind_verified_manifest(DIGEST, 2, manifest_bytes=MANIFEST)
    assert journal.verified_manifest_bytes() == MANIFEST
    payload = journal.load().payload
    assert payload["manifest_sha256"] == DIGEST
    assert payload["manifest_attempts_started"] == 3
    assert [item["state"] for item in payload["targets"]] == [
        "UNSTARTED",
        "UNSTARTED",
    ]


def test_offer_recheck_atomically_binds_readiness_digest_and_never_rebinds(
    tmp_path,
):
    journal = _journal(tmp_path)
    initial = journal.create()
    assert initial.payload["manifest_sha256"] is None

    bound = journal.mark_offer_rechecked(DIGEST)
    assert bound.state == "OFFER_RECHECKED"
    assert bound.payload["manifest_sha256"] == DIGEST
    assert bound.payload["manifest_attempts_started"] == 0

    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        journal.mark_offer_rechecked("7" * 64)
    assert journal.load().payload["manifest_sha256"] == DIGEST


def test_verified_manifest_only_verifies_the_existing_at_t_binding(tmp_path):
    other_manifest = jcs_canonical_bytes(
        {
            "schema_version": "ln_church.http_get_batch_manifest.v1",
            "method": "GET",
            "urls": ["https://example.com/other"],
        }
    )
    other_digest = hashlib.sha256(other_manifest).hexdigest()
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()

    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        journal.bind_verified_manifest(
            other_digest, 1, manifest_bytes=other_manifest
        )
    failed = journal.load()
    assert failed.state == "MANIFEST_FETCH_STARTED"
    assert failed.payload["manifest_sha256"] == DIGEST
    assert failed.payload["manifest_bytes_b64"] is None

    verified = journal.bind_verified_manifest(
        DIGEST, 2, manifest_bytes=MANIFEST
    )
    assert verified.payload["manifest_sha256"] == DIGEST


def test_failure_report_preserves_non_null_at_t_manifest_binding(tmp_path):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()
    report = _failure_report()
    frozen = journal.freeze_report(
        report,
        submission_id=SUBMISSION_ID,
        manifest_fetch_outcome="release_timeout",
    )
    assert frozen.state == "REPORT_FROZEN"
    assert frozen.payload["manifest_sha256"] == DIGEST
    assert frozen.payload["manifest_bytes_b64"] is None
    assert journal.frozen_report_bytes() == report


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observed_sha256", None),
        ("http_status", None),
        ("elapsed_ms", None),
        ("unexpected", True),
    ],
)
def test_failure_report_rejects_null_placeholders_and_unknown_fields(
    tmp_path, field, value
):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()
    report = json.loads(_failure_report().decode("utf-8"))
    report["manifest_fetch"][field] = value
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.freeze_report(
            jcs_canonical_bytes(report),
            submission_id=SUBMISSION_ID,
            manifest_fetch_outcome="release_timeout",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("http_status", None), ("elapsed_ms", None), ("unexpected", True)],
)
def test_non_http_target_rejects_null_placeholders_and_unknown_fields(
    tmp_path, field, value
):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()
    journal.bind_verified_manifest(DIGEST, 2, manifest_bytes=MANIFEST)
    journal.mark_target_attempt_started(0)
    journal.record_target_result(
        0, "http_response", http_status=200, elapsed_ms=1
    )
    journal.mark_target_attempt_started(1)
    journal.record_target_result(1, "timeout", elapsed_ms=2)
    report = json.loads(_report().decode("utf-8"))
    report["results"][1][field] = value
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.freeze_report(
            jcs_canonical_bytes(report),
            submission_id=SUBMISSION_ID,
            manifest_fetch_outcome="retrieved",
        )


def test_frozen_report_definition_tuple_must_equal_genesis_binding(tmp_path):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()
    report = json.loads(_failure_report().decode("utf-8"))
    report["task_definition_digest"] = "8" * 64
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.freeze_report(
            jcs_canonical_bytes(report),
            submission_id=SUBMISSION_ID,
            manifest_fetch_outcome="release_timeout",
        )
    snapshot = journal.load()
    assert snapshot.state == "MANIFEST_FETCH_STARTED"
    assert snapshot.payload["task_definition_digest"] == DEFINITION_DIGEST


def test_checksum_valid_post_init_null_manifest_binding_fails_closed(tmp_path):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    envelope = json.loads(journal.path.read_text(encoding="utf-8"))
    envelope["payload"]["manifest_sha256"] = None
    envelope["checksum"] = hashlib.sha256(
        JOURNAL_CHECKSUM_DOMAIN + jcs_canonical_bytes(envelope["payload"])
    ).hexdigest()
    journal.path.write_bytes(jcs_canonical_bytes(envelope) + b"\n")
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.load()


def test_attempt_started_is_durable_before_result_and_never_replayable(tmp_path):
    journal = _journal(tmp_path)
    journal.create()
    journal.mark_offer_rechecked(DIGEST)
    journal.start_manifest_attempt()
    journal.bind_verified_manifest(DIGEST, 2, manifest_bytes=MANIFEST)
    journal.mark_target_attempt_started(0)
    assert journal.load().state == "ATTEMPT_STARTED"
    assert journal.resume_disposition() == "target_interrupted_indeterminate"
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        journal.mark_target_attempt_started(0)
    journal.record_target_result(0, "interrupted_indeterminate")
    journal.mark_target_attempt_started(1)
    journal.record_target_result(1, "http_response", http_status=204, elapsed_ms=4)
    assert [item["outcome"] for item in journal.load().payload["targets"]] == [
        "interrupted_indeterminate",
        "http_response",
    ]


@pytest.mark.parametrize("source", ["receipt", "status"])
def test_report_bytes_are_frozen_and_bound_ack_is_one_atomic_transition(
    source, tmp_path
):
    journal = _journal(tmp_path)
    report = _freeze_retrieved_report(journal)
    assert journal.frozen_report_bytes() == report
    assert journal.resume_disposition() == "completion_dispatch"
    attempted = journal.mark_completion_dispatch_attempted()
    assert attempted.state == "REPORT_FROZEN"
    assert attempted.payload["completion_dispatch_attempts"] == 1
    assert journal.resume_disposition() == "completion_status_first"
    acked = journal.mark_compound_completion_acked(_acknowledgement(source))
    assert acked.state == "COMPOUND_COMPLETION_ACKED"
    assert journal.compound_acknowledgement_facts()["source"] == source
    assert journal.resume_disposition() == "status_only"
    terminal = journal.mark_terminal_status(_terminal_status())
    assert terminal.payload["terminal_status"]["terminal"] is True
    assert journal.resume_disposition() == "status_only"


def test_reasonless_pending_status_is_accepted_without_synthetic_reason(tmp_path):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    status = _acknowledgement("status")["status"]
    status["evaluation"] = {"state": "PENDING"}
    acknowledgement = ScheduledCompletionAcknowledgement(
        source="status",
        status=ScheduledRewardStatus.model_validate(status),
    )

    snapshot = journal.mark_compound_completion_acked(acknowledgement)

    assert snapshot.state == "COMPOUND_COMPLETION_ACKED"
    assert journal.compound_acknowledgement_facts()["source"] == "status"
    assert "reason" not in status["evaluation"]
    recovered = _journal(tmp_path).load()
    assert recovered.state == "COMPOUND_COMPLETION_ACKED"


def test_reasonless_terminal_status_is_persisted_and_recovered_verbatim(tmp_path):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    journal.mark_compound_completion_acked(_acknowledgement("receipt"))
    status = _terminal_status()
    status["evaluation"] = {"state": "APPROVED"}
    status_model = ScheduledRewardStatus.model_validate(status)

    snapshot = journal.mark_terminal_status(status_model)

    assert snapshot.payload["terminal_status"] == status
    envelope = json.loads(journal.path.read_text(encoding="utf-8"))
    persisted_evaluation = envelope["payload"]["terminal_status"]["evaluation"]
    assert persisted_evaluation == {"state": "APPROVED"}
    assert "reason" not in persisted_evaluation
    recovered = _journal(tmp_path).load()
    assert recovered.payload["terminal_status"] == status


@pytest.mark.parametrize("reason", [None, "", "x" * 129])
def test_present_evaluation_reason_remains_bounded_nonempty(reason, tmp_path):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    status = _acknowledgement("status")["status"]
    status["evaluation"] = {"state": "PENDING", "reason": reason}

    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.mark_compound_completion_acked(
            {"source": "status", "status": status}
        )
    assert journal.load().state == "REPORT_FROZEN"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda status: status["evaluation"].update(unexpected=True),
        lambda status: status["base_reward"].update(
            entitlement_state="CONFIRMING"
        ),
        lambda status: status["reference_bonus"].update(
            decision_state="AWARDED"
        ),
        lambda status: status["reference_bonus"].update(
            settlement_state="PAID_CONFIRMED"
        ),
        lambda status: status.update(retry_after_seconds=0),
        lambda status: status.update(terminal=True),
        lambda status: status.update(retry_after_seconds=3601),
    ],
)
def test_corrected_nested_status_shape_rejects_invalid_variants(
    mutate, tmp_path
):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    status = _acknowledgement("status")["status"]
    mutate(status)

    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.mark_compound_completion_acked(
            {"source": "status", "status": status}
        )
    assert journal.load().state == "REPORT_FROZEN"


@pytest.mark.parametrize(
    "status",
    [
        _acknowledgement("status")["status"],
        _terminal_status(report_id="report_other"),
        _terminal_status(report_sha256="6" * 64),
    ],
)
def test_terminal_transition_requires_authoritative_bound_terminal_status(
    status, tmp_path
):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    journal.mark_compound_completion_acked(_acknowledgement("receipt"))
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.mark_terminal_status(status)
    snapshot = journal.load()
    assert snapshot.state == "COMPOUND_COMPLETION_ACKED"
    assert snapshot.payload["terminal_status"] is None


def test_terminal_transition_rejects_missing_evidence_argument(tmp_path):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    journal.mark_compound_completion_acked(_acknowledgement("status"))
    with pytest.raises(TypeError):
        journal.mark_terminal_status()
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "other"),
        ("task_definition_digest", "8" * 64),
        ("manifest_sha256", "7" * 64),
        ("submission_id", "sub_" + "d" * 32),
        ("report_sha256", "6" * 64),
        ("receipt_state", "PENDING"),
    ],
)
def test_malformed_or_unbound_ack_never_creates_terminal_boundary(
    field, value, tmp_path
):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.mark_compound_completion_acked(
            _acknowledgement("status", **{field: value})
        )
    snapshot = journal.load()
    assert snapshot.state == "REPORT_FROZEN"
    assert snapshot.payload["compound_ack"] is None


def test_incomplete_ack_and_ack_before_any_dispatch_fail_closed(tmp_path):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        journal.mark_compound_completion_acked(_acknowledgement())
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.mark_compound_completion_acked(
            {"source": "status", "status": {"task_id": TASK_ID}}
        )
    assert journal.load().state == "REPORT_FROZEN"


@pytest.mark.parametrize("source", ["receipt", "status"])
def test_unknown_or_source_incompatible_ack_fields_are_not_silently_dropped(
    source, tmp_path
):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    acknowledgement = _acknowledgement(source)
    acknowledgement[source]["claim_token"] = "A" * 43
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.mark_compound_completion_acked(acknowledgement)
    assert journal.load().state == "REPORT_FROZEN"

    if source == "status":
        acknowledgement = _acknowledgement(source)
        acknowledgement[source]["completion_id"] = "completion_1"
        with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
            journal.mark_compound_completion_acked(acknowledgement)
        assert journal.load().state == "REPORT_FROZEN"


def test_dispatch_attempt_auxiliary_metadata_enforces_exactly_two_maximum(tmp_path):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    first = journal.mark_completion_dispatch_attempted()
    second = journal.mark_completion_dispatch_attempted()
    assert first.state == second.state == "REPORT_FROZEN"
    assert second.payload["completion_dispatch_attempts"] == 2
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        journal.mark_completion_dispatch_attempted()
    assert journal.load().payload["completion_dispatch_attempts"] == 2


@pytest.mark.parametrize(
    "invalid_state",
    ["COMPLETION_DISPATCHED", "REPORT_ACCEPTED", "COMPOUND_COMPLETION_ACKED"],
)
def test_removed_or_incomplete_top_level_completion_states_fail_checksum_valid_read(
    invalid_state, tmp_path
):
    journal = _journal(tmp_path)
    _freeze_retrieved_report(journal)
    journal.mark_completion_dispatch_attempted()
    envelope = json.loads(journal.path.read_text(encoding="utf-8"))
    envelope["payload"]["state"] = invalid_state
    envelope["payload"]["compound_ack"] = None
    envelope["checksum"] = hashlib.sha256(
        JOURNAL_CHECKSUM_DOMAIN + jcs_canonical_bytes(envelope["payload"])
    ).hexdigest()
    journal.path.write_bytes(jcs_canonical_bytes(envelope) + b"\n")
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.load()


@pytest.mark.parametrize("stage", ["before_replace", "after_replace"])
def test_dispatch_marker_replace_failure_leaves_old_or_new_frozen_state(
    stage, tmp_path
):
    clean = _journal(tmp_path)
    _freeze_retrieved_report(clean)

    def fail(current):
        if current == stage:
            raise OSError("injected")

    faulted = _journal(tmp_path, fault_hook=fail)
    with pytest.raises(JournalPersistenceError, match="^JOURNAL_PERSISTENCE_AMBIGUOUS$"):
        faulted.mark_completion_dispatch_attempted()
    recovered = _journal(tmp_path).load()
    assert recovered.state == "REPORT_FROZEN"
    assert recovered.payload["completion_dispatch_attempts"] in {0, 1}
    expected = (
        "completion_status_first"
        if recovered.payload["completion_dispatch_attempts"]
        else "completion_dispatch"
    )
    assert _journal(tmp_path).resume_disposition() == expected


@pytest.mark.parametrize("stage", ["before_replace", "after_replace"])
def test_atomic_ack_replace_failure_leaves_valid_frozen_or_bound_acked_state(
    stage, tmp_path
):
    clean = _journal(tmp_path)
    _freeze_retrieved_report(clean)
    clean.mark_completion_dispatch_attempted()

    def fail(current):
        if current == stage:
            raise OSError("injected")

    faulted = _journal(tmp_path, fault_hook=fail)
    with pytest.raises(JournalPersistenceError, match="^JOURNAL_PERSISTENCE_AMBIGUOUS$"):
        faulted.mark_compound_completion_acked(_acknowledgement("receipt"))
    recovered = _journal(tmp_path)
    assert recovered.load().state in {"REPORT_FROZEN", "COMPOUND_COMPLETION_ACKED"}
    if recovered.load().state == "COMPOUND_COMPLETION_ACKED":
        assert recovered.compound_acknowledgement_facts()["receipt_state"] == (
            "DURABLY_ACCEPTED"
        )


def test_secret_bearing_payload_is_rejected_before_persistence(tmp_path):
    journal = _journal(tmp_path)
    journal.create()
    envelope = json.loads(journal.path.read_text(encoding="utf-8"))
    envelope["payload"]["claim_token"] = "A" * 43
    journal.path.write_text(json.dumps(envelope), encoding="utf-8")
    if os.name != "nt":
        os.chmod(journal.path, 0o600)
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        journal.load()


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
def test_any_persistence_failure_is_reported_ambiguous_and_stops(stage, tmp_path):
    armed = False

    def fail(current):
        if armed and current == stage:
            raise OSError("injected")

    journal = _journal(tmp_path, fault_hook=fail)
    journal.create()
    armed = True
    with pytest.raises(JournalPersistenceError, match="^JOURNAL_PERSISTENCE_AMBIGUOUS$"):
        journal.mark_offer_rechecked(DIGEST)
    # A replacement may or may not have reached the namespace; either result
    # is valid and checksummed, and the caller was told not to continue I/O.
    recovered = _journal(tmp_path).load()
    assert recovered.state in {"INIT", "OFFER_RECHECKED"}
    if recovered.state == "INIT":
        assert recovered.payload["manifest_sha256"] is None
    else:
        assert recovered.payload["manifest_sha256"] == DIGEST
