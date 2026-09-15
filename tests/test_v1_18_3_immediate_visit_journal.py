"""Focused SDK-R3/R4/A02/A07/A09/A13 examples from exact audited specification.

All URLs, credentials and bodies are synthetic. No network operation is used.
"""
import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ln_church_agent.immediate_visit import ImmediateVisitExecutor
from ln_church_agent.immediate_visit_journal import ImmediateVisitJournal
from ln_church_agent.immediate_visit_models import FrozenImmediateVisitReport, ImmediateVisitClaimCredential, ImmediateVisitCompletionResult
from ln_church_agent.network_fetch import ImmediateVisitFetchResponse, ImmediateVisitFetchError
from ln_church_agent.task_journal import JournalError, JournalPersistenceError
import ln_church_agent.immediate_visit as worker
import ln_church_agent.immediate_visit_journal as storage


def claim_value(count=10):
    urls = ["https://example.com/path/%s" % index for index in range(count)]
    return dict(
        schema_version="ln_church.agent_task_claim_response.immediate_visit.v1",
        task_id="task_" + "a" * 32, task_type="immediate_http_visit.v1",
        execution_id="exe_" + "b" * 32, claim_token="s" * 43,
        claimed_at="2026-09-14T00:00:00.123Z", report_deadline="2026-09-14T00:10:00.123Z",
        reward_address="0x" + "1" * 40, reward_address_control_verified=False,
        profile_id="immediate_visit_utf8.v1", repeat_policy="once_per_endpoint",
        endpoints=[dict(endpoint_id="ep_" + hashlib.sha256(url.encode()).hexdigest(), url=url) for url in urls],
        reward=dict(network="eip155:8453", asset="USDC",
                    asset_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    base_amount_atomic="7500", bonus_amount_atomic="7500", maximum_amount_atomic="15000"))


@pytest.fixture
def private_dir(tmp_path):
    os.chmod(str(tmp_path), 0o700)
    return tmp_path


def test_tenth_endpoint_only_and_saved_exact_report(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value())
    journal = ImmediateVisitJournal(private_dir, claim)
    calls = []
    def fetch(url):
        calls.append(url)
        return ImmediateVisitFetchResponse(404, (("Content-Type", "application/json"),), b'{"time":"10:00","count":1}')
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", fetch)
    report = ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[-1].endpoint_id)
    assert calls == [claim.endpoints[-1].url]
    assert report.report.observation.status == 404
    # Architecture §12.1, independent fixed expected digest.
    assert report.report.observation.structure_sha256 == "46cbfebaf99e6099753552f61c4a151a4af463d345452fd9bb03db64d40f625a"
    restored = ImmediateVisitJournal.load_claim(private_dir, claim.task_id, claim.execution_id)
    reopened = ImmediateVisitJournal(private_dir, restored)
    replay = ImmediateVisitExecutor(journal=reopened).execute(restored, restored.endpoints[-1].endpoint_id)
    assert replay.canonical_bytes == report.canonical_bytes
    assert replay.report_sha256 == report.report_sha256
    assert len(calls) == 1
    with pytest.raises(JournalError):
        ImmediateVisitExecutor(journal=reopened).execute(restored, restored.endpoints[0].endpoint_id)
    assert len(calls) == 1


def test_failed_start_record_does_not_get(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal = ImmediateVisitJournal(private_dir, claim)
    calls = []
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", lambda url: calls.append(url))
    def failed_write(*args):
        raise JournalPersistenceError()
    monkeypatch.setattr(storage, "_write", failed_write)
    with pytest.raises(JournalPersistenceError):
        ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[0].endpoint_id)
    assert calls == []


def test_interrupted_started_fetch_recovers_lost_without_get(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal = ImmediateVisitJournal(private_dir, claim)
    with journal.fetch_operation_guard():
        journal.begin_fetch(claim, claim.endpoints[0].endpoint_id, "2026-09-14T00:00:01.123Z")
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", lambda url: pytest.fail("repeat target GET"))
    report = ImmediateVisitExecutor(journal=ImmediateVisitJournal(private_dir, claim)).execute(claim, claim.endpoints[0].endpoint_id)
    assert report.report.observation.reason == "fetch_outcome_lost"
    assert "body_sha256" not in json.loads(report.canonical_bytes)["observation"]
    assert report.report.observation.fetch_started_at == "2026-09-14T00:00:01.123Z"


def test_parallel_executor_cannot_repeat_or_replace_live_get(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal1 = ImmediateVisitJournal(private_dir, claim)
    journal2 = ImmediateVisitJournal(private_dir, claim)
    entered, release = threading.Event(), threading.Event()
    calls = []
    def fetch(url):
        calls.append(url)
        entered.set()
        assert release.wait(3)
        return ImmediateVisitFetchResponse(200, (("Content-Type", "application/json"),), b'{"ok":true}')
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", fetch)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(ImmediateVisitExecutor(journal=journal1).execute, claim, claim.endpoints[0].endpoint_id)
        try:
            assert entered.wait(3)
            with pytest.raises(JournalError, match="JOURNAL_LOCKED"):
                ImmediateVisitExecutor(journal=journal2).execute(claim, claim.endpoints[0].endpoint_id)
        finally:
            release.set()
        first = future.result()
    second = ImmediateVisitExecutor(journal=journal2).execute(claim, claim.endpoints[0].endpoint_id)
    assert second.canonical_bytes == first.canonical_bytes
    assert len(calls) == 1


def test_privacy_token_separate_body_title_header_never_saved(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    body = b'<title>RAW_PRIVATE_TITLE</title><p>Bearer RAW_BODY_SECRET</p>'
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", lambda url:
                        ImmediateVisitFetchResponse(402, (("Content-Type", "text/html"),
                                                          ("Set-Cookie", "RAW_COOKIE_SECRET")), body))
    journal = ImmediateVisitJournal(private_dir, claim)
    report = ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[0].endpoint_id)
    assert report.report.observation.outcome == "comparable"
    assert report.report.observation.status == 402
    surfaces = journal.path.read_text() + repr(report) + repr(claim) + repr(journal)
    for secret in ("RAW_PRIVATE_TITLE", "RAW_BODY_SECRET", "RAW_COOKIE_SECRET", "s" * 43):
        assert secret not in surfaces
    assert "s" * 43 in journal.credential_path.read_text()
    if os.name != "nt":
        assert journal.credential_path.stat().st_mode & 0o777 == 0o600
        assert journal.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("reason", ["fetch_timeout", "body_incomplete", "dns_disallowed", "peer_mismatch"])
def test_transport_failure_no_digest_or_endpoint_switch(private_dir, monkeypatch, reason):
    claim = ImmediateVisitClaimCredential(**claim_value())
    calls = []
    def fail(url):
        calls.append(url)
        raise ImmediateVisitFetchError(reason)
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", fail)
    journal = ImmediateVisitJournal(private_dir, claim)
    executor = ImmediateVisitExecutor(journal=journal)
    report = executor.execute(claim, claim.endpoints[4].endpoint_id)
    assert report.report.observation.reason == reason
    assert "structure_sha256" not in json.loads(report.canonical_bytes)["observation"]
    executor.execute(claim, claim.endpoints[4].endpoint_id)
    assert calls == [claim.endpoints[4].url]


def test_altered_report_never_replaces_frozen_bytes(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", lambda url:
                        ImmediateVisitFetchResponse(200, (("Content-Type", "application/json"),), b'{"ok":true}'))
    journal = ImmediateVisitJournal(private_dir, claim)
    report = ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[0].endpoint_id)
    payload = json.loads(report.canonical_bytes)
    payload["observation"]["fetch_finished_at"] = "2026-09-14T00:00:10.000Z"
    different = FrozenImmediateVisitReport.from_report(payload)
    with pytest.raises(JournalError):
        journal.prepare_report(claim, different)
    assert journal.load_report(claim).canonical_bytes == report.canonical_bytes


def test_claim_snapshot_change_rejected_without_fetch(private_dir):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal = ImmediateVisitJournal(private_dir, claim)
    changed = claim_value(1)
    changed["reward_address"] = "0x" + "2" * 40
    with pytest.raises(JournalError):
        journal.require_binding(ImmediateVisitClaimCredential(**changed))


def test_damaged_journal_does_not_start_get(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal = ImmediateVisitJournal(private_dir, claim)
    journal.path.write_bytes(b'{"payload":{},"sha256":"invalid"}')
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", lambda url: pytest.fail("target GET"))
    with pytest.raises(JournalError):
        ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[0].endpoint_id)


@pytest.mark.parametrize("state", ["accepted", "unknown", "rejected"])
def test_only_definite_unaccepted_correction_preserves_same_get(private_dir, monkeypatch, state):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    calls = []
    def fetch(url):
        calls.append(url)
        return ImmediateVisitFetchResponse(200, (("Content-Type", "application/json"),), b'{"ok":true}')
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", fetch)
    journal = ImmediateVisitJournal(private_dir, claim)
    report = ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[0].endpoint_id)
    journal.record_dispatch(claim, report)
    journal.record_result(claim, report, ImmediateVisitCompletionResult(state=state, error_code="invalid_request"))
    payload = json.loads(report.canonical_bytes)
    payload["submission_id"] = "sub_" + "f" * 32
    corrected = FrozenImmediateVisitReport.from_report(payload)
    if state == "rejected":
        saved = journal.correct_unaccepted_report(claim, corrected)
        assert saved.canonical_bytes == corrected.canonical_bytes
        assert not journal.completion_started(claim, corrected)
        assert ImmediateVisitExecutor(journal=journal).execute(claim, claim.endpoints[0].endpoint_id).canonical_bytes == corrected.canonical_bytes
    else:
        with pytest.raises(JournalError):
            journal.correct_unaccepted_report(claim, corrected)
        assert journal.load_report(claim).canonical_bytes == report.canonical_bytes
    assert len(calls) == 1


def test_missing_existing_journal_never_reinitializes_claim(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal = ImmediateVisitJournal(private_dir, claim)
    journal.path.unlink()
    monkeypatch.setattr(worker, "fetch_immediate_visit_once", lambda url: pytest.fail("target GET"))
    recovered = ImmediateVisitJournal.load_claim(private_dir, claim.task_id, claim.execution_id)
    with pytest.raises(JournalError, match="JOURNAL_MISSING"):
        ImmediateVisitJournal(private_dir, recovered)


def test_interrupted_initialization_before_credential_is_resumable(private_dir, monkeypatch):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    original_write = storage._write
    def fail_credential(path, payload):
        if path.name.endswith(".credential.json"):
            raise JournalPersistenceError()
        original_write(path, payload)
    monkeypatch.setattr(storage, "_write", fail_credential)
    with pytest.raises(JournalPersistenceError):
        ImmediateVisitJournal(private_dir, claim)
    monkeypatch.setattr(storage, "_write", original_write)
    journal = ImmediateVisitJournal(private_dir, claim)
    assert journal.load_report(claim) is None
    assert ImmediateVisitJournal.load_claim(private_dir, claim.task_id, claim.execution_id).execution_id == claim.execution_id


@pytest.mark.parametrize("suffix", [b'{"secret":"RAW_CREDENTIAL_SECRET",', b'\xffRAW_CREDENTIAL_SECRET'])
def test_private_decoder_error_has_no_secret_exception_graph(private_dir, suffix):
    claim = ImmediateVisitClaimCredential(**claim_value(1))
    journal = ImmediateVisitJournal(private_dir, claim)
    journal.credential_path.write_bytes(suffix)
    with pytest.raises(JournalError) as caught:
        ImmediateVisitJournal.load_claim(private_dir, claim.task_id, claim.execution_id)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "RAW_CREDENTIAL_SECRET" not in repr(caught.value)
