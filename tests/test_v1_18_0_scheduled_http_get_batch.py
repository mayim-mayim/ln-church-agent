from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import pickle
import sys

import pytest

from ln_church_agent import (
    ScheduledExecutionContext as PublicScheduledExecutionContext,
    ScheduledHTTPGetBatchExecutor as PublicScheduledHTTPGetBatchExecutor,
    ScheduledHttpGetBatchExecutor as PublicScheduledHttpGetBatchExecutor,
)
from ln_church_agent.network_fetch import FetchResponse, NetworkFetchError
from ln_church_agent.scheduled_http_get_batch import (
    ScheduledExecutionContext,
    ScheduledExecutionError,
    ScheduledHTTPGetBatchExecutor,
)
from ln_church_agent.task_contract import jcs_canonical_bytes
from ln_church_agent.task_journal import TaskJournal


TASK_ID = "task_scheduled_batch"
HANDLE = "cred_" + "3" * 64
DEFINITION_DIGEST = "4" * 64
SIGNED_QUERY_TOKEN = "V18_SECRET_SERIAL_SENTINEL_7f39c214"
SIGNED_URL = (
    "https://tasks-release.mayim-mayim.com/release.json?Policy="
    + SIGNED_QUERY_TOKEN
    + "&Signature=opaque"
)


class _Clock:
    def __init__(self, now):
        self.now = now
        self.tick = 100.0

    def utcnow(self):
        return self.now

    def monotonic(self):
        return self.tick

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        self.tick += seconds


class _Connector:
    def __init__(
        self,
        manifest_responses,
        target_responses=(),
        before_target=None,
        before_manifest=None,
    ):
        self.manifest_responses = list(manifest_responses)
        self.target_responses = list(target_responses)
        self.manifest_urls = []
        self.target_urls = []
        self.before_target = before_target
        self.before_manifest = before_manifest

    def fetch_manifest(self, url):
        self.manifest_urls.append(url)
        if self.before_manifest is not None:
            self.before_manifest(len(self.manifest_urls) - 1)
        value = self.manifest_responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def fetch_target(self, url):
        self.target_urls.append(url)
        if self.before_target is not None:
            self.before_target(len(self.target_urls) - 1)
        value = self.target_responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def _manifest(*urls):
    return jcs_canonical_bytes(
        {
            "schema_version": "ln_church.http_get_batch_manifest.v1",
            "method": "GET",
            "urls": list(urls),
        }
    )


def _context(clock, manifest):
    scheduled = clock.now.replace(microsecond=0)
    return ScheduledExecutionContext(
        task_id=TASK_ID,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        scheduled_at=scheduled.strftime("%Y-%m-%dT%H:%M:%SZ"),
        new_target_start_before=(scheduled + timedelta(seconds=300)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        report_close_at=(scheduled + timedelta(seconds=600)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        local_claim_credential_handle=HANDLE,
        _signed_manifest_url=SIGNED_URL,
    )


def _context_constructor_fields(context):
    return {
        "task_id": context.task_id,
        "task_type": context.task_type,
        "task_definition_version": context.task_definition_version,
        "task_definition_digest": context.task_definition_digest,
        "manifest_sha256": context.manifest_sha256,
        "scheduled_at": context.scheduled_at,
        "new_target_start_before": context.new_target_start_before,
        "report_close_at": context.report_close_at,
        "local_claim_credential_handle": (
            context.local_claim_credential_handle
        ),
        "_signed_manifest_url": SIGNED_URL,
        "execution_available": context.execution_available,
        "release_state": context.release_state,
    }


def _journal(tmp_path, manifest_sha256):
    journal = TaskJournal(
        tmp_path / "run.journal",
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
    )
    journal.create()
    snapshot = journal.mark_offer_rechecked(manifest_sha256)
    assert snapshot.state == "OFFER_RECHECKED"
    assert snapshot.payload["manifest_sha256"] == manifest_sha256
    return journal


def _status_ack(context, frozen, *, terminal=False):
    evaluation = {
        "state": "PENDING",
        "reason": "STRUCTURALLY_VALID",
    }
    base_reward = {
        "entitlement_state": "DUE",
        "settlement_state": "CONFIRMING",
    }
    reference_bonus = {
        "candidate": True,
        "decision_state": "PENDING",
    }
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
        "source": "status",
        "status": {
            "schema_version": "ln_church.agent_task_reward_status.v2",
            "task_id": context.task_id,
            "task_type": context.task_type,
            "task_definition_version": context.task_definition_version,
            "task_definition_digest": context.task_definition_digest,
            "manifest_sha256": frozen.report.manifest_sha256,
            "submission_id": frozen.submission_id,
            "report_id": "report_1",
            "report_sha256": frozen.sha256,
            "accepted_at": "2026-08-20T03:04:42Z",
            "receipt_state": "DURABLY_ACCEPTED",
            "evaluation": evaluation,
            "base_reward": base_reward,
            "reference_bonus": reference_bonus,
            "terminal": terminal,
            "retry_after_seconds": retry_after_seconds,
        },
    }


def test_context_repr_and_string_redact_signed_manifest_url():
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    context = _context(clock, _manifest("https://example.com/a"))
    assert SIGNED_URL not in repr(context)
    assert SIGNED_URL not in str(context)
    assert "REDACTED" in str(context)


def test_context_signed_query_is_outside_normal_serialization_surfaces(
    caplog, capsys
):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    context = _context(clock, _manifest("https://example.com/a"))
    caplog.set_level(logging.INFO)
    logging.getLogger("v18-secret-boundary").info("context=%r", context)
    print(context)
    print(repr(context), file=sys.stderr)

    failures = []
    for operation in (
        lambda: vars(context),
        lambda: asdict(context),
        lambda: pickle.dumps(context),
        lambda: json.dumps(context, default=vars),
    ):
        with pytest.raises((TypeError, ValueError)) as caught:
            operation()
        failures.append(str(caught.value))

    captured = capsys.readouterr()
    surfaces = "\n".join(
        [
            repr(context),
            str(context),
            caplog.text,
            captured.out,
            captured.err,
        ]
        + failures
    )
    assert SIGNED_URL not in surfaces
    assert SIGNED_QUERY_TOKEN not in surfaces
    assert not hasattr(context, "__dict__")
    assert context._manifest_url_value() == SIGNED_URL


@pytest.mark.parametrize(
    ("target_offset", "report_offset"),
    [(299, 600), (301, 600), (300, 599), (300, 601)],
)
def test_context_requires_fixture_exact_t_plus_five_and_t_plus_ten(
    target_offset, report_offset
):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    valid = _context(clock, _manifest("https://example.com/a"))
    scheduled = clock.now.replace(microsecond=0)
    fields = _context_constructor_fields(valid)
    fields["new_target_start_before"] = (
        scheduled + timedelta(seconds=target_offset)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    fields["report_close_at"] = (
        scheduled + timedelta(seconds=report_offset)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(
        ScheduledExecutionError, match="^EXECUTION_CONTEXT_INVALID$"
    ):
        ScheduledExecutionContext(**fields)


def test_sequential_execution_writes_attempt_started_before_each_target_io(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a", "https://example.com/b")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)

    def assert_durable(position):
        payload = journal.load().payload
        assert payload["state"] == "ATTEMPT_STARTED"
        assert payload["targets"][position]["state"] == "ATTEMPT_STARTED"

    connector = _Connector(
        [FetchResponse(200, {}, manifest)],
        [FetchResponse(204, {}), FetchResponse(503, {})],
        before_target=assert_durable,
    )
    executor = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    )
    frozen = executor.execute(context, journal=journal)
    assert connector.target_urls == ["https://example.com/a", "https://example.com/b"]
    assert [item.outcome for item in frozen.report.results] == [
        "http_response",
        "http_response",
    ]
    assert [item.http_status for item in frozen.report.results] == [204, 503]
    assert frozen.exact_bytes == frozen.report.canonical_bytes()
    assert frozen.sha256 == hashlib.sha256(frozen.exact_bytes).hexdigest()
    assert journal.load().state == "REPORT_FROZEN"


def test_at_t_manifest_digest_is_durable_before_first_manifest_io(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)

    def assert_bound(_attempt):
        snapshot = journal.load()
        assert snapshot.state == "MANIFEST_FETCH_STARTED"
        assert snapshot.payload["manifest_sha256"] == context.manifest_sha256

    connector = _Connector(
        [NetworkFetchError("encoding_unsupported")],
        before_manifest=assert_bound,
    )
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert frozen.report.manifest_fetch.outcome == "release_encoding_unsupported"
    assert journal.load().payload["manifest_sha256"] == context.manifest_sha256


def test_manifest_retries_exact_same_url_at_most_three_attempts(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    connector = _Connector(
        [
            NetworkFetchError("dns_error"),
            FetchResponse(503, {}),
            FetchResponse(200, {}, manifest),
        ],
        [FetchResponse(200, {})],
    )
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.manifest_urls == [SIGNED_URL, SIGNED_URL, SIGNED_URL]
    assert journal.load().payload["manifest_attempts_started"] == 3
    assert frozen.report.manifest_fetch.outcome == "retrieved"


def test_manifest_policy_failure_is_not_retried_and_has_no_targets(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    connector = _Connector([NetworkFetchError("encoding_unsupported")])
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.manifest_urls == [SIGNED_URL]
    assert connector.target_urls == []
    assert frozen.report.manifest_fetch.outcome == "release_encoding_unsupported"
    assert frozen.report.results == []
    assert journal.load().payload["manifest_sha256"] == context.manifest_sha256


@pytest.mark.parametrize(
    ("expected_bytes", "response_bytes", "expected_outcome"),
    [
        (
            _manifest("https://example.com/a"),
            _manifest("https://example.com/other"),
            "release_digest_mismatch",
        ),
        (b"{", b"{", "release_invalid_json"),
        (
            jcs_canonical_bytes(
                {
                    "schema_version": "ln_church.http_get_batch_manifest.v1",
                    "method": "POST",
                    "urls": ["https://example.com/a"],
                }
            ),
            jcs_canonical_bytes(
                {
                    "schema_version": "ln_church.http_get_batch_manifest.v1",
                    "method": "POST",
                    "urls": ["https://example.com/a"],
                }
            ),
            "release_schema_invalid",
        ),
    ],
)
def test_digest_or_manifest_validation_failure_retains_at_t_binding(
    expected_bytes, response_bytes, expected_outcome, tmp_path
):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    context = _context(clock, expected_bytes)
    journal = _journal(tmp_path, context.manifest_sha256)
    connector = _Connector([FetchResponse(200, {}, response_bytes)])
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)

    assert frozen.report.manifest_fetch.outcome == expected_outcome
    assert frozen.report.manifest_sha256 == context.manifest_sha256
    assert frozen.report.results == []
    assert connector.target_urls == []
    payload = journal.load().payload
    assert payload["state"] == "REPORT_FROZEN"
    assert payload["manifest_sha256"] == context.manifest_sha256
    assert payload["manifest_bytes_b64"] is None


def test_readiness_unavailable_never_unlocks_target_access(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    ready = _context(clock, manifest)
    context = ScheduledExecutionContext(
        **{
            **_context_constructor_fields(ready),
            "execution_available": False,
            "release_state": "UNAVAILABLE",
        }
    )
    journal = _journal(tmp_path, context.manifest_sha256)
    connector = _Connector([FetchResponse(200, {}, manifest)])
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.target_urls == []
    assert frozen.report.manifest_fetch.outcome == "release_protocol_error"
    assert frozen.report.results == []
    assert journal.load().payload["manifest_sha256"] == context.manifest_sha256


def test_target_failure_is_one_attempt_and_next_target_continues(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a", "https://example.com/b")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    connector = _Connector(
        [FetchResponse(200, {}, manifest)],
        [NetworkFetchError("timeout"), FetchResponse(200, {})],
    )
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.target_urls == ["https://example.com/a", "https://example.com/b"]
    assert [item.outcome for item in frozen.report.results] == [
        "timeout",
        "http_response",
    ]


def test_t_plus_five_cutoff_records_all_unattempted_without_target_io(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a", "https://example.com/b")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    connector = _Connector([FetchResponse(200, {}, manifest)])
    # Manifest response is available, but no new target may start at T+5.
    original_fetch = connector.fetch_manifest

    def fetch_and_advance(url):
        response = original_fetch(url)
        clock.advance(300)
        return response

    connector.fetch_manifest = fetch_and_advance
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.target_urls == []
    assert [item.outcome for item in frozen.report.results] == [
        "not_attempted_deadline",
        "not_attempted_deadline",
    ]


def test_restart_after_target_dispatch_never_resends_indeterminate_target(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a", "https://example.com/b")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    journal.start_manifest_attempt()
    journal.bind_verified_manifest(
        context.manifest_sha256, 2, manifest_bytes=manifest
    )
    journal.mark_target_attempt_started(0)
    connector = _Connector([], [FetchResponse(204, {})])
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.target_urls == ["https://example.com/b"]
    assert [item.outcome for item in frozen.report.results] == [
        "interrupted_indeterminate",
        "http_response",
    ]


def test_restart_during_manifest_attempt_fails_closed_without_network(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    journal.start_manifest_attempt()
    connector = _Connector([])
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=connector, monotonic=clock.monotonic, utcnow=clock.utcnow
    ).execute(context, journal=journal)
    assert connector.manifest_urls == []
    assert connector.target_urls == []
    assert frozen.report.manifest_fetch.outcome == "release_interrupted"
    assert frozen.report.results == []
    assert journal.load().payload["manifest_sha256"] == context.manifest_sha256


@pytest.mark.parametrize(
    "resume_state", ["OFFER_RECHECKED", "MANIFEST_FETCH_STARTED"]
)
def test_resumed_readiness_digest_mismatch_fails_before_any_network_io(
    resume_state, tmp_path
):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    if resume_state == "MANIFEST_FETCH_STARTED":
        journal.start_manifest_attempt()
    assert journal.load().state == resume_state
    mismatched = _context(clock, _manifest("https://example.com/other"))
    connector = _Connector([])

    with pytest.raises(
        ScheduledExecutionError, match="^EXECUTION_JOURNAL_INVALID$"
    ):
        ScheduledHTTPGetBatchExecutor(
            connector=connector,
            monotonic=clock.monotonic,
            utcnow=clock.utcnow,
        ).execute(mismatched, journal=journal)
    assert connector.manifest_urls == []
    assert connector.target_urls == []
    assert journal.load().payload["manifest_sha256"] == context.manifest_sha256


@pytest.mark.parametrize(
    "executor_type",
    [
        ScheduledHTTPGetBatchExecutor,
        PublicScheduledHTTPGetBatchExecutor,
        PublicScheduledHttpGetBatchExecutor,
    ],
    ids=["module-export", "top-level-export", "top-level-alias"],
)
def test_public_executor_direct_init_fails_closed_without_write_or_network(
    executor_type, monkeypatch, tmp_path
):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    constructed = _context(clock, manifest)
    context = PublicScheduledExecutionContext(
        **_context_constructor_fields(constructed)
    )

    journal = TaskJournal(
        tmp_path / "direct-init.journal",
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
    )
    journal.create()
    before = journal.load()
    raw_before = journal.path.read_bytes()
    binding_calls = []

    def unexpected_binding(manifest_sha256):
        binding_calls.append(manifest_sha256)
        raise AssertionError("Executor must not own readiness binding")

    monkeypatch.setattr(journal, "mark_offer_rechecked", unexpected_binding)
    connector = _Connector([])
    with pytest.raises(ScheduledExecutionError, match="^EXECUTION_JOURNAL_INVALID$"):
        executor_type(
            connector=connector,
            monotonic=clock.monotonic,
            utcnow=clock.utcnow,
        ).execute(context, journal=journal)

    after = journal.load()
    assert binding_calls == []
    assert connector.manifest_urls == []
    assert connector.target_urls == []
    assert journal.path.read_bytes() == raw_before
    assert before.state == after.state == "INIT"
    assert before.sequence == after.sequence == 0
    assert before.payload["manifest_sha256"] is None
    assert after.payload["manifest_sha256"] is None


@pytest.mark.parametrize("terminal_status", [False, True])
def test_compound_ack_boundary_reloads_exact_report_with_zero_network_io(
    terminal_status, tmp_path
):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = _journal(tmp_path, context.manifest_sha256)
    initial_connector = _Connector(
        [FetchResponse(200, {}, manifest)], [FetchResponse(200, {})]
    )
    frozen = ScheduledHTTPGetBatchExecutor(
        connector=initial_connector,
        monotonic=clock.monotonic,
        utcnow=clock.utcnow,
    ).execute(context, journal=journal)
    journal.mark_completion_dispatch_attempted()
    journal.mark_compound_completion_acked(_status_ack(context, frozen))
    if terminal_status:
        journal.mark_terminal_status(
            _status_ack(context, frozen, terminal=True)["status"]
        )

    no_io_connector = _Connector([])
    resumed = ScheduledHTTPGetBatchExecutor(
        connector=no_io_connector,
        monotonic=clock.monotonic,
        utcnow=clock.utcnow,
    ).execute(context, journal=journal)
    assert resumed.exact_bytes == frozen.exact_bytes
    assert resumed.sha256 == frozen.sha256
    assert no_io_connector.manifest_urls == []
    assert no_io_connector.target_urls == []
    assert journal.resume_disposition() == "status_only"


def test_missing_journal_is_not_silently_recreated(tmp_path):
    clock = _Clock(datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc))
    manifest = _manifest("https://example.com/a")
    context = _context(clock, manifest)
    journal = TaskJournal(
        tmp_path / "missing.journal",
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
    )
    with pytest.raises(ScheduledExecutionError, match="^EXECUTION_JOURNAL_INVALID$"):
        ScheduledHTTPGetBatchExecutor(
            connector=_Connector([]),
            monotonic=clock.monotonic,
            utcnow=clock.utcnow,
        ).execute(context, journal=journal)
