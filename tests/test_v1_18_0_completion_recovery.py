from datetime import datetime, timezone
import hashlib
import json
import threading

import pytest

from ln_church_agent.task_journal import (
    JournalError,
    JournalPersistenceError,
    TaskJournal,
)
from ln_church_agent.task_v2_client import AgentTaskV2Client
from ln_church_agent.task_v2_models import (
    ManifestFetchResult,
    ScheduledCompletionReport,
    ScheduledTargetResult,
    ScheduledTaskClaimResponse,
    ScheduledTaskReadiness,
)
from ln_church_agent.task_v2_transport import (
    CompletionOutcomeUnknownError,
    TaskV2RawResponse,
    TaskV2Transport,
)


TOKEN = "A" * 43
SIGNED_URL = "https://tasks-release.mayim-mayim.com/opaque?Policy=secret"
DEFINITION = "a" * 64
MANIFEST_BYTES = (
    b'{"method":"GET","schema_version":'
    b'"ln_church.http_get_batch_manifest.v1",'
    b'"urls":["https://example.com/a"]}'
)
MANIFEST = hashlib.sha256(MANIFEST_BYTES).hexdigest()
SUBMISSION = "sub_" + "b" * 32


@pytest.fixture(autouse=True)
def _stable_completion_clock(monkeypatch):
    original_init = AgentTaskV2Client.__init__

    def stable_init(self, *args, **kwargs):
        kwargs.setdefault(
            "utcnow",
            lambda: datetime(
                2026, 8, 20, 3, 4, 41, tzinfo=timezone.utc
            ),
        )
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(AgentTaskV2Client, "__init__", stable_init)


def _response(status, payload):
    return TaskV2RawResponse(
        status_code=status,
        headers={"content-type": "application/json"},
        body=json.dumps(payload, separators=(",", ":")).encode(),
    )


def _credential(*, task_definition_digest=DEFINITION):
    response = ScheduledTaskClaimResponse.model_validate(
        {
            "schema_version": "ln_church.agent_task_claim_response.v2",
            "task_id": "task_1",
            "task_type": "scheduled_http_get_batch.v1",
            "task_definition_version": "1.0.0",
            "task_definition_digest": task_definition_digest,
            "claim_token": TOKEN,
            "claim_expires_at": "2026-08-20T03:10:00Z",
            "scheduled_at": "2026-08-20T03:00:00Z",
            "report_close_at": "2026-08-20T03:10:00Z",
            "manifest_url": SIGNED_URL,
            "manifest_url_not_before": "2026-08-20T03:00:00Z",
            "manifest_url_expires_at": "2026-08-20T03:10:00Z",
            "reward_address": "0x0000000000000000000000000000000000000001",
            "reward_address_control_verified": False,
            "reward": {
                "network": "eip155:8453",
                "asset": "USDC",
                "asset_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount_atomic": "10000",
            },
        }
    )
    return response.to_credential(agent_id="agent_1")


def _report():
    return ScheduledCompletionReport(
        submission_id=SUBMISSION,
        task_definition_digest=DEFINITION,
        manifest_sha256=MANIFEST,
        manifest_fetch=ManifestFetchResult(
            outcome="retrieved",
            http_status=200,
            observed_sha256=MANIFEST,
            elapsed_ms=20,
        ),
        results=[
            ScheduledTargetResult(
                position=0,
                target_url="https://example.com/a",
                outcome="http_response",
                http_status=200,
                elapsed_ms=15,
            )
        ],
        completed_at="2026-08-20T03:04:40Z",
    )


def _receipt(report_bytes):
    return {
        "schema_version": "ln_church.agent_task_completion_receipt.v2",
        "task_id": "task_1",
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DEFINITION,
        "manifest_sha256": MANIFEST,
        "submission_id": SUBMISSION,
        "report_id": "report_1",
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "completion_id": "completion_1",
        "accepted_at": "2026-08-20T03:04:42Z",
        "receipt_state": "DURABLY_ACCEPTED",
        "evaluation_state": "PENDING",
    }


def _status(report_bytes, terminal=False):
    evaluation = {"state": "PENDING", "reason": "STRUCTURALLY_VALID"}
    base_reward = {
        "entitlement_state": "DUE",
        "settlement_state": "CONFIRMING",
    }
    reference_bonus = {"candidate": True, "decision_state": "PENDING"}
    retry_after_seconds = 15
    if terminal:
        evaluation = {"state": "APPROVED", "reason": "STRUCTURALLY_VALID"}
        base_reward = {
            "entitlement_state": "TERMINAL",
            "settlement_state": "PAID_CONFIRMED",
        }
        reference_bonus = {"candidate": False, "decision_state": "NOT_AWARDED"}
        retry_after_seconds = 0
    return {
        "schema_version": "ln_church.agent_task_reward_status.v2",
        "task_id": "task_1",
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DEFINITION,
        "manifest_sha256": MANIFEST,
        "submission_id": SUBMISSION,
        "report_id": "report_1",
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "accepted_at": "2026-08-20T03:04:42Z",
        "receipt_state": "DURABLY_ACCEPTED",
        "evaluation": evaluation,
        "base_reward": base_reward,
        "reference_bonus": reference_bonus,
        "terminal": terminal,
        "retry_after_seconds": retry_after_seconds,
    }


def _not_found():
    return _response(404, {"error_code": "not_found"})


def _readiness_payload(manifest_sha256=MANIFEST):
    return {
        "schema_version": "ln_church.agent_task_readiness.v1",
        "task_id": "task_1",
        "offer_status": "RUNNING",
        "execution_available": True,
        "release_state": "READY",
        "manifest_sha256": manifest_sha256,
        "manifest_url": SIGNED_URL,
        "manifest_url_expires_at": "2026-08-20T03:10:00Z",
        "new_target_start_before": "2026-08-20T03:05:00Z",
        "report_close_at": "2026-08-20T03:10:00Z",
    }


def _pre_t_readiness_payload():
    return {
        "schema_version": "ln_church.agent_task_readiness.v1",
        "task_id": "task_1",
        "offer_status": "ESTABLISHED",
        "execution_available": False,
        "release_state": "PREPARING",
        "manifest_sha256": None,
        "manifest_url": SIGNED_URL,
        "manifest_url_not_before": "2026-08-20T03:00:00Z",
        "manifest_url_expires_at": "2026-08-20T03:10:00Z",
        "retry_at": "2026-08-20T03:00:00Z",
        "new_target_start_before": None,
        "report_close_at": None,
    }


def _unavailable_readiness_payload():
    payload = _readiness_payload()
    payload["execution_available"] = False
    payload["release_state"] = "UNAVAILABLE"
    return payload


def _readiness_journal(path, credential, *, fault_hook=None):
    return TaskJournal(
        path,
        task_id=credential.task_id,
        local_claim_credential_handle=credential.local_claim_credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
        fault_hook=fault_hook,
    )


def _journal(tmp_path, credential, report):
    journal = TaskJournal(
        tmp_path / "completion.journal",
        task_id=credential.task_id,
        local_claim_credential_handle=credential._local_fingerprint(),
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    journal.create()
    journal.mark_offer_rechecked(MANIFEST)
    journal.start_manifest_attempt()
    journal.bind_verified_manifest(
        MANIFEST, 1, manifest_bytes=MANIFEST_BYTES
    )
    journal.mark_target_attempt_started(0)
    journal.record_target_result(
        0, "http_response", http_status=200, elapsed_ms=15
    )
    journal.freeze_report(
        report.canonical_bytes(),
        submission_id=report.submission_id,
        manifest_fetch_outcome="retrieved",
    )
    return journal


def test_get_readiness_durably_binds_before_return_and_context_is_verify_only(
    tmp_path,
):
    credential = _credential()
    journal = _readiness_journal(
        tmp_path / "readiness.journal", credential
    )
    journal.create()
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, bytes(body)))
        return _response(200, _readiness_payload())

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    first = client.get_readiness(credential, journal=journal)
    payload = journal.load().payload
    assert payload["state"] == "OFFER_RECHECKED"
    assert payload["sequence"] == 1
    assert payload["manifest_sha256"] == MANIFEST
    persisted = journal.path.read_text(encoding="utf-8")
    assert MANIFEST in persisted
    assert TOKEN not in persisted
    assert SIGNED_URL not in persisted
    assert "Policy=secret" not in persisted

    context = client.build_execution_context(
        credential,
        first,
        journal=journal,
    )
    assert context.manifest_sha256 == MANIFEST
    payload = journal.load().payload
    assert payload["state"] == "OFFER_RECHECKED"
    assert payload["sequence"] == 1
    assert payload["manifest_sha256"] == MANIFEST
    assert calls == [("GET", "/api/agent/tasks/task_1/readiness", b"")]


@pytest.mark.parametrize(
    "later_payload",
    [_readiness_payload("d" * 64), _pre_t_readiness_payload()],
    ids=["changed-digest", "null-after-binding"],
)
def test_reopened_readiness_binding_rejects_replacement_before_return(
    later_payload, tmp_path
):
    credential = _credential()
    path = tmp_path / "reopened-readiness.journal"
    first_journal = _readiness_journal(path, credential)
    first_journal.create()
    first_client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: _response(200, _readiness_payload())
        )
    )
    first_client.get_readiness(credential, journal=first_journal)
    first_payload = first_journal.load().payload
    assert first_payload["manifest_sha256"] == MANIFEST

    # Model a process loss/restart by discarding the first journal and client
    # instances, then reopening only the durable on-disk identity.
    reopened = _readiness_journal(path, credential)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path))
        return _response(200, later_payload)

    resumed = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        resumed.get_readiness(credential, journal=reopened)
    after = reopened.load().payload
    assert after["state"] == "OFFER_RECHECKED"
    assert after["sequence"] == first_payload["sequence"]
    assert after["manifest_sha256"] == MANIFEST
    assert calls == [("GET", "/api/agent/tasks/task_1/readiness")]


def test_reopened_same_digest_readiness_does_not_rebind(tmp_path):
    credential = _credential()
    path = tmp_path / "same-readiness.journal"
    journal = _readiness_journal(path, credential)
    journal.create()
    calls = []

    def exchange(method, request_path, query, headers, body):
        calls.append((method, request_path))
        return _response(200, _readiness_payload())

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    client.get_readiness(credential, journal=journal)
    first = journal.load().payload
    reopened = _readiness_journal(path, credential)
    same = client.get_readiness(credential, journal=reopened)
    after = reopened.load().payload
    assert same.manifest_sha256 == MANIFEST
    assert after["state"] == "OFFER_RECHECKED"
    assert after["manifest_sha256"] == MANIFEST
    assert after["sequence"] == first["sequence"] == 1
    assert calls == [
        ("GET", "/api/agent/tasks/task_1/readiness"),
        ("GET", "/api/agent/tasks/task_1/readiness"),
    ]


def test_pre_t_null_readiness_leaves_journal_init_and_unbound(tmp_path):
    credential = _credential()
    journal = _readiness_journal(tmp_path / "pre-t.journal", credential)
    journal.create()
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: _response(
                200, _pre_t_readiness_payload()
            )
        )
    )
    readiness = client.get_readiness(credential, journal=journal)
    payload = journal.load().payload
    assert readiness.manifest_sha256 is None
    assert payload["state"] == "INIT"
    assert payload["sequence"] == 0
    assert payload["manifest_sha256"] is None


def test_unavailable_readiness_with_digest_binds_before_return(tmp_path):
    credential = _credential()
    journal = _readiness_journal(
        tmp_path / "unavailable.journal", credential
    )
    journal.create()
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: _response(
                200, _unavailable_readiness_payload()
            )
        )
    )
    readiness = client.get_readiness(credential, journal=journal)
    payload = journal.load().payload
    assert readiness.release_state == "UNAVAILABLE"
    assert readiness.execution_available is False
    assert readiness.manifest_sha256 == MANIFEST
    assert payload["state"] == "OFFER_RECHECKED"
    assert payload["sequence"] == 1
    assert payload["manifest_sha256"] == MANIFEST


def test_build_execution_context_cannot_bind_caller_readiness_to_init(
    tmp_path,
):
    credential = _credential()
    readiness = ScheduledTaskReadiness.model_validate(_readiness_payload())
    journal = _readiness_journal(
        tmp_path / "caller-readiness.journal", credential
    )
    journal.create()
    before = journal.path.read_bytes()
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: pytest.fail("unexpected Venue I/O")
        )
    )
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        client.build_execution_context(
            credential,
            readiness,
            journal=journal,
        )
    assert journal.path.read_bytes() == before
    assert journal.load().state == "INIT"
    assert journal.load().payload["manifest_sha256"] is None


@pytest.mark.parametrize(
    "failure_stage",
    ["before_temp_write", "before_replace", "after_replace"],
)
def test_readiness_binding_ambiguity_returns_nothing_and_stops_downstream_io(
    failure_stage, tmp_path
):
    credential = _credential()
    armed = False

    def fail(stage):
        if armed and stage == failure_stage:
            raise OSError("injected readiness binding failure")

    path = tmp_path / (failure_stage + ".journal")
    journal = _readiness_journal(path, credential, fault_hook=fail)
    journal.create()
    armed = True
    calls = []

    def exchange(method, request_path, query, headers, body):
        calls.append((method, request_path))
        return _response(200, _readiness_payload())

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    with pytest.raises(
        JournalPersistenceError,
        match="^JOURNAL_PERSISTENCE_AMBIGUOUS$",
    ):
        client.get_readiness(credential, journal=journal)
    assert calls == [("GET", "/api/agent/tasks/task_1/readiness")]

    recovered = _readiness_journal(path, credential).load()
    assert recovered.state in {"INIT", "OFFER_RECHECKED"}
    if recovered.state == "INIT":
        assert recovered.payload["manifest_sha256"] is None
    else:
        assert recovered.payload["manifest_sha256"] == MANIFEST


def test_readiness_rejects_definition_rebinding_before_transport(tmp_path):
    original = _credential()
    changed = _credential(task_definition_digest="d" * 64)
    assert changed.local_claim_credential_handle == (
        original.local_claim_credential_handle
    )
    journal = TaskJournal(
        tmp_path / "definition-readiness.journal",
        task_id=original.task_id,
        local_claim_credential_handle=(
            original.local_claim_credential_handle
        ),
        task_type=original.task_type,
        task_definition_version=original.task_definition_version,
        task_definition_digest=original.task_definition_digest,
    )
    journal.create()
    before = journal.path.read_bytes()
    calls = []

    def exchange(*args):
        calls.append(args)
        return _response(200, _readiness_payload())

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        client.get_readiness(changed, journal=journal)
    assert calls == []
    assert journal.path.read_bytes() == before


@pytest.mark.parametrize("state", ["MANIFEST_FETCH_STARTED", "REPORT_FROZEN"])
def test_readiness_rejects_post_fetch_states_before_transport(tmp_path, state):
    credential = _credential()
    if state == "REPORT_FROZEN":
        journal = _journal(tmp_path, credential, _report())
    else:
        journal = TaskJournal(
            tmp_path / "post-fetch-readiness.journal",
            task_id=credential.task_id,
            local_claim_credential_handle=(
                credential.local_claim_credential_handle
            ),
            task_type=credential.task_type,
            task_definition_version=credential.task_definition_version,
            task_definition_digest=credential.task_definition_digest,
        )
        journal.create()
        journal.mark_offer_rechecked(MANIFEST)
        journal.start_manifest_attempt()
    before = journal.path.read_bytes()
    calls = []

    def exchange(*args):
        calls.append(args)
        return _response(200, _readiness_payload())

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        client.get_readiness(credential, journal=journal)
    assert calls == []
    assert journal.path.read_bytes() == before


def test_execution_context_requires_the_bound_journal(tmp_path):
    credential = _credential()
    readiness = ScheduledTaskReadiness.model_validate(_readiness_payload())
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: pytest.fail("unexpected Venue I/O")
        )
    )
    with pytest.raises(TypeError):
        client.build_execution_context(credential, readiness)


def test_execution_context_rejects_caller_selected_execution_id(tmp_path):
    credential = _credential()
    readiness = ScheduledTaskReadiness.model_validate(_readiness_payload())
    journal = TaskJournal(
        tmp_path / "derived-execution.journal",
        task_id=credential.task_id,
        local_claim_credential_handle=credential.local_claim_credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    journal.create()
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: pytest.fail("unexpected Venue I/O")
        )
    )

    with pytest.raises(TypeError):
        client.build_execution_context(
            credential,
            readiness,
            journal=journal,
            execution_id="caller_selected_execution",
        )
    assert journal.load().state == "INIT"


@pytest.mark.parametrize(
    "journal_state",
    ["OFFER_RECHECKED", "MANIFEST_FETCH_STARTED"],
)
@pytest.mark.parametrize(
    "operation",
    ["complete_task", "recover_completion"],
)
def test_pre_report_digest_mismatch_blocks_all_completion_io(
    journal_state,
    operation,
    tmp_path,
):
    credential = _credential()
    journal = TaskJournal(
        tmp_path / (journal_state.lower() + ".journal"),
        task_id=credential.task_id,
        local_claim_credential_handle=credential.local_claim_credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    journal.create()
    journal.mark_offer_rechecked(MANIFEST)
    if journal_state == "MANIFEST_FETCH_STARTED":
        journal.start_manifest_attempt()
    assert journal.load().state == journal_state

    different_digest = "d" * 64
    report = _report().model_copy(
        update={
            "manifest_sha256": different_digest,
            "manifest_fetch": ManifestFetchResult(
                outcome="retrieved",
                http_status=200,
                observed_sha256=different_digest,
                elapsed_ms=20,
            ),
        }
    )
    calls = []
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: calls.append(args)
        )
    )

    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        getattr(client, operation)(credential, report, journal=journal)
    snapshot = journal.load()
    assert snapshot.state == journal_state
    assert snapshot.payload["manifest_sha256"] == MANIFEST
    assert calls == []


def test_completion_requires_explicit_bound_journal_before_network_io():
    report = _report()
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        return _response(202, _receipt(report.canonical_bytes()))

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    with pytest.raises(TypeError):
        client.complete_task(_credential(), report)
    assert calls == []


@pytest.mark.parametrize("operation", ["complete_task", "recover_completion"])
def test_definition_tuple_mismatch_fails_before_journal_or_network_io(
    operation, tmp_path, monkeypatch
):
    report = _report()
    original = _credential()
    journal = _journal(tmp_path, original, report)
    changed_digest = "d" * 64
    changed = _credential(task_definition_digest=changed_digest)
    assert changed.local_claim_credential_handle == original.local_claim_credential_handle
    changed_report = report.model_copy(
        update={"task_definition_digest": changed_digest}
    )
    journal_reads = []
    network_calls = []
    original_load = journal.load

    def observed_load():
        journal_reads.append(True)
        return original_load()

    monkeypatch.setattr(journal, "load", observed_load)
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: network_calls.append(args)
        )
    )

    with pytest.raises(JournalError, match="^JOURNAL_INVALID$"):
        getattr(client, operation)(changed, changed_report, journal=journal)
    assert journal_reads == []
    assert network_calls == []


def test_unambiguous_completion_returns_atomic_compound_ack(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, bytes(body)))
        return _response(202, _receipt(report_bytes))

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    ack = client.complete_task(credential, report, journal=journal)
    assert ack.source == "receipt"
    assert ack.receipt.receipt_state == "DURABLY_ACCEPTED"
    assert calls == [("POST", "/api/agent/tasks/task_1/completion", report_bytes)]
    payload = journal.load().payload
    assert payload["state"] == "COMPOUND_COMPLETION_ACKED"
    assert payload["completion_dispatch_attempts"] == 1
    assert payload["compound_ack"] is not None
    serialized = journal.path.read_text(encoding="utf-8")
    assert '"state":"REPORT_ACCEPTED"' not in serialized
    assert "COMPLETION_DISPATCHED" not in serialized


def test_ambiguous_completion_keeps_report_frozen_until_status_ack(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, dict(headers), bytes(body)))
        if len(calls) == 1:
            raise CompletionOutcomeUnknownError()
        payload = journal.load().payload
        assert payload["state"] == "REPORT_FROZEN"
        assert payload["completion_dispatch_attempts"] == 1
        return _response(200, _status(report_bytes))

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    ack = client.complete_task(credential, report, journal=journal)
    assert ack.source == "status"
    assert [call[0] for call in calls] == ["POST", "GET"]
    assert "X-LN-Task-Claim-Token" not in calls[1][2]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


def test_absent_before_close_resends_same_submission_and_exact_frozen_bytes_once(
    tmp_path,
):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, dict(headers), bytes(body)))
        if len(calls) == 1:
            raise CompletionOutcomeUnknownError()
        if len(calls) == 2:
            return _not_found()
        payload = journal.load().payload
        assert payload["state"] == "REPORT_FROZEN"
        assert payload["completion_dispatch_attempts"] == 2
        return _response(202, _receipt(report_bytes))

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange),
        utcnow=lambda: datetime(2026, 8, 20, 3, 5, tzinfo=timezone.utc),
    )
    ack = client.complete_task(credential, report, journal=journal)
    assert ack.source == "receipt"
    assert [call[0] for call in calls] == ["POST", "GET", "POST"]
    assert calls[0][3] == calls[2][3] == report_bytes
    assert calls[0][2]["Idempotency-Key"] == calls[2][2]["Idempotency-Key"]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


def test_absent_at_or_after_close_never_resends(tmp_path):
    report = _report()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    journal.mark_completion_dispatch_attempted()
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path))
        return _not_found()

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange),
        utcnow=lambda: datetime(2026, 8, 20, 3, 10, tzinfo=timezone.utc),
    )
    with pytest.raises(CompletionOutcomeUnknownError):
        client.recover_completion(credential, report, journal=journal)
    assert [call[0] for call in calls] == ["GET"]
    payload = journal.load().payload
    assert payload["state"] == "REPORT_FROZEN"
    assert payload["completion_dispatch_attempts"] == 1


def test_recovery_without_dispatch_fact_is_status_only_and_never_posts(tmp_path):
    report = _report()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        return _not_found()

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange),
        utcnow=lambda: datetime(2026, 8, 20, 3, 5, tzinfo=timezone.utc),
    )
    with pytest.raises(CompletionOutcomeUnknownError):
        client.recover_completion(credential, report, journal=journal)
    assert calls == ["GET"]
    assert journal.load().payload["completion_dispatch_attempts"] == 0


def test_fresh_completion_at_close_never_posts(tmp_path):
    report = _report()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []
    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=lambda *args: calls.append(args)),
        utcnow=lambda: datetime(2026, 8, 20, 3, 10, tzinfo=timezone.utc),
    )
    with pytest.raises(CompletionOutcomeUnknownError):
        client.complete_task(credential, report, journal=journal)
    assert calls == []
    assert journal.load().payload["completion_dispatch_attempts"] == 0


def test_status_binding_mismatch_fails_closed_without_resend(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path))
        if len(calls) == 1:
            raise CompletionOutcomeUnknownError()
        status = _status(report_bytes)
        status["manifest_sha256"] = "d" * 64
        return _response(200, status)

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    with pytest.raises(Exception) as caught:
        client.complete_task(credential, report, journal=journal)
    assert getattr(caught.value, "code", None) == "TASK_V2_RESPONSE_INVALID"
    assert len(calls) == 2
    assert journal.load().state == "REPORT_FROZEN"


@pytest.mark.parametrize("source", ["receipt", "status"])
def test_durable_ack_accepted_at_must_be_inside_claim_window(
    source, tmp_path
):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        if source == "status" and method == "POST":
            raise CompletionOutcomeUnknownError()
        payload = (
            _receipt(report_bytes)
            if source == "receipt"
            else _status(report_bytes)
        )
        payload["accepted_at"] = "2026-08-20T03:10:00Z"
        return _response(202 if method == "POST" else 200, payload)

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    with pytest.raises(Exception) as caught:
        client.complete_task(credential, report, journal=journal)
    assert getattr(caught.value, "code", None) == "TASK_V2_RESPONSE_INVALID"
    assert journal.load().state == "REPORT_FROZEN"


def test_two_ambiguous_dispatches_are_never_followed_by_third_post(tmp_path):
    report = _report()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        if method == "POST":
            raise CompletionOutcomeUnknownError()
        return _not_found()

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange),
        utcnow=lambda: datetime(2026, 8, 20, 3, 5, tzinfo=timezone.utc),
    )
    with pytest.raises(CompletionOutcomeUnknownError):
        client.complete_task(credential, report, journal=journal)
    assert calls == ["POST", "GET", "POST", "GET"]
    payload = journal.load().payload
    assert payload["state"] == "REPORT_FROZEN"
    assert payload["completion_dispatch_attempts"] == 2

    calls.clear()
    with pytest.raises(CompletionOutcomeUnknownError):
        client.recover_completion(credential, report, journal=journal)
    assert calls == ["GET"]
    assert journal.load().payload["completion_dispatch_attempts"] == 2


def test_restart_with_dispatch_attempt_is_status_first_then_direct_ack(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    journal.mark_completion_dispatch_attempted()
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, dict(headers)))
        return _response(200, _status(report_bytes))

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    ack = client.recover_completion(
        credential, report, journal=journal
    )
    assert ack.source == "status"
    assert [item[0] for item in calls] == ["GET"]
    assert "X-LN-Task-Claim-Token" not in calls[0][1]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


def test_existing_receipt_after_close_is_recovered_without_post(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    journal.mark_completion_dispatch_attempted()
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        return _response(200, _status(report_bytes))

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange),
        utcnow=lambda: datetime(2026, 8, 20, 3, 11, tzinfo=timezone.utc),
    )
    ack = client.recover_completion(credential, report, journal=journal)
    assert ack.source == "status"
    assert calls == ["GET"]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


def test_no_completion_post_after_compound_ack_boundary(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, dict(headers)))
        if method == "POST":
            return _response(202, _receipt(report_bytes))
        return _response(200, _status(report_bytes))

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    client.complete_task(credential, report, journal=journal)
    ack = client.complete_task(credential, report, journal=journal)
    assert ack.source == "status"
    assert [item[0] for item in calls] == ["POST", "GET"]
    assert calls[1][1] == (
        "/api/agent/tasks/task_1/submissions/" + SUBMISSION + "/status"
    )
    assert "X-LN-Task-Claim-Token" not in calls[1][2]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


def test_two_workers_are_serialized_across_post_ack_and_return(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    first_journal = _journal(tmp_path, credential, report)
    second_journal = TaskJournal(
        first_journal.path,
        task_id=credential.task_id,
        local_claim_credential_handle=credential.local_claim_credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    first_post_started = threading.Event()
    allow_first_receipt = threading.Event()
    calls = []
    calls_lock = threading.Lock()

    def exchange(method, path, query, headers, body):
        with calls_lock:
            calls.append((method, path))
        if method == "POST":
            first_post_started.set()
            if not allow_first_receipt.wait(timeout=5):
                pytest.fail("timed out waiting to release first Completion")
            return _response(202, _receipt(report_bytes))
        return _response(200, _status(report_bytes))

    first_client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    second_client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange)
    )
    first_result = []
    first_errors = []

    def first_worker():
        try:
            first_result.append(
                first_client.complete_task(
                    credential, report, journal=first_journal
                )
            )
        except BaseException as error:
            first_errors.append(error)

    worker = threading.Thread(target=first_worker, name="completion-worker-1")
    worker.start()
    assert first_post_started.wait(timeout=5)
    try:
        with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
            second_client.recover_completion(
                credential, report, journal=second_journal
            )
        with calls_lock:
            assert calls == [
                ("POST", "/api/agent/tasks/task_1/completion")
            ]
    finally:
        allow_first_receipt.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert first_errors == []
    assert len(first_result) == 1
    assert first_result[0].source == "receipt"

    # A later contender reads the durable ACK and is status-only.  It can
    # observe terminality but can never issue a late Completion POST.
    late = second_client.complete_task(
        credential, report, journal=second_journal
    )
    assert late.source == "status"
    with calls_lock:
        assert [method for method, _path in calls].count("POST") == 1
        assert [method for method, _path in calls] == ["POST", "GET"]


def test_post_ack_status_must_match_persisted_server_receipt_facts(tmp_path):
    report = _report()
    report_bytes = report.canonical_bytes()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        if method == "POST":
            return _response(202, _receipt(report_bytes))
        status = _status(report_bytes)
        status["report_id"] = "different_report"
        return _response(200, status)

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    client.complete_task(credential, report, journal=journal)
    with pytest.raises(Exception) as caught:
        client.complete_task(credential, report, journal=journal)
    assert getattr(caught.value, "code", None) == "TASK_V2_RESPONSE_INVALID"
    assert calls == ["POST", "GET"]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


def test_journal_report_or_claim_binding_mismatch_fails_before_post(tmp_path):
    report = _report()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    different = report.model_copy(update={"submission_id": "sub_" + "d" * 32})
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append(method)
        return _response(202, _receipt(report.canonical_bytes()))

    client = AgentTaskV2Client(transport=TaskV2Transport(exchange=exchange))
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        client.complete_task(credential, different, journal=journal)
    assert calls == []


def test_frozen_completion_cannot_replace_journal_bound_manifest_digest(tmp_path):
    report = _report()
    credential = _credential()
    journal = _journal(tmp_path, credential, report)
    different_digest = "d" * 64
    different = report.model_copy(
        update={
            "manifest_sha256": different_digest,
            "manifest_fetch": ManifestFetchResult(
                outcome="retrieved",
                http_status=200,
                observed_sha256=different_digest,
                elapsed_ms=20,
            ),
        }
    )
    calls = []
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: calls.append(args)
        )
    )
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        client.complete_task(credential, different, journal=journal)
    payload = journal.load().payload
    assert payload["state"] == "REPORT_FROZEN"
    assert payload["manifest_sha256"] == MANIFEST
    assert calls == []


def test_frozen_report_urls_must_equal_verified_manifest_order(tmp_path):
    credential = _credential()
    wrong_report = _report().model_copy(
        update={
            "results": [
                ScheduledTargetResult(
                    position=0,
                    target_url="https://example.com/b",
                    outcome="http_response",
                    http_status=200,
                    elapsed_ms=15,
                )
            ]
        }
    )
    journal = _journal(tmp_path, credential, wrong_report)
    calls = []
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: calls.append(args)
        )
    )
    with pytest.raises(JournalError, match="^JOURNAL_STATE_CONFLICT$"):
        client.complete_task(credential, wrong_report, journal=journal)
    assert calls == []
