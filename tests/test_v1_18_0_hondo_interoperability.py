from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

import pytest
from pydantic import ValidationError

from ln_church_agent.task_journal import TaskJournal
from ln_church_agent.task_v2_contract import canonical_completion_bytes
from ln_church_agent.task_v2_client import AgentTaskV2Client
from ln_church_agent.task_v2_models import (
    ManifestFetchResult,
    ScheduledCompletionAcknowledgement,
    ScheduledCompletionReceipt,
    ScheduledCompletionReport,
    ScheduledHttpGetBatchTask,
    ScheduledRewardStatus,
    ScheduledTargetResult,
    ScheduledTaskClaimResponse,
    ScheduledTaskReadiness,
)
from ln_church_agent.task_v2_transport import (
    TaskV2RawResponse,
    TaskV2Transport,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    ROOT / "tests/fixtures/v18-hondo-oracle-833dca3-interoperability.json"
)
SUBMISSION_SCHEMA_PATH = (
    ROOT / "tests/fixtures/v18-hondo-submission-schema-833dca3.json"
)
RESULT_SCHEMA_PATH = (
    ROOT / "tests/fixtures/v18-hondo-result-schema-833dca3.json"
)

FIXTURE_BYTES = 26216
FIXTURE_SHA256 = (
    "0483b2c400bd2372a11ce6508cc2966289bcae0a80b2fc9f4b8ed8b82b18b9f9"
)
SUBMISSION_SCHEMA_BYTES = 4956
SUBMISSION_SCHEMA_BLOB = "3a26dcb49bfb0865977af228cd2ad1bb7d52ba83"
SUBMISSION_SCHEMA_SHA256 = (
    "5190c2d46219fbe0ccab5f5d7eeb826099dbab81257c1030713abeaf03f295fd"
)
RESULT_SCHEMA_BYTES = 3442
RESULT_SCHEMA_BLOB = "67ecfc7bac2c03a0511d962a95a314f4a8e96610"
RESULT_SCHEMA_SHA256 = (
    "26583967562650e2336c46f1a5525074cd3b76b4ee9fcd067a0a4b744ab6d277"
)

HONDO_COMMIT = "833dca3b804f5b82ca0607c524d9c354f2d62378"
HONDO_TREE = "61c51a84a7a912d51d55f0e6273b2748a5902c58"
HONDO_PARENT = "5a20d10489b177a9eba54ae545f3247ce163e2b1"
PUBLIC_PRODUCER = "921540f979e26ba63b3a2eb8deb9ba8d7da58b40"
LIFECYCLE_PRODUCER = "fdfba9c65b3228d754c368c9c755883ea33028cb"
NETWORK_PRODUCER = "9403b2958c2a95601703c59e3f5e673ba0e63c12"
WHOLE_SECOND_Z = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)


def _exact_json(
    path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
    expected_blob: str | None = None,
) -> dict[str, Any]:
    raw = path.read_bytes()
    assert len(raw) == expected_bytes
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    if expected_blob is not None:
        git_object = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        assert hashlib.sha1(git_object).hexdigest() == expected_blob
    value = json.loads(raw.decode("utf-8", errors="strict"))
    assert type(value) is dict
    return value


@pytest.fixture(scope="module")
def oracle() -> dict[str, Any]:
    return _exact_json(
        FIXTURE_PATH,
        expected_bytes=FIXTURE_BYTES,
        expected_sha256=FIXTURE_SHA256,
    )


@pytest.fixture(scope="module")
def submission_schema() -> dict[str, Any]:
    return _exact_json(
        SUBMISSION_SCHEMA_PATH,
        expected_bytes=SUBMISSION_SCHEMA_BYTES,
        expected_sha256=SUBMISSION_SCHEMA_SHA256,
        expected_blob=SUBMISSION_SCHEMA_BLOB,
    )


@pytest.fixture(scope="module")
def result_schema() -> dict[str, Any]:
    return _exact_json(
        RESULT_SCHEMA_PATH,
        expected_bytes=RESULT_SCHEMA_BYTES,
        expected_sha256=RESULT_SCHEMA_SHA256,
        expected_blob=RESULT_SCHEMA_BLOB,
    )


def _same_json_scalar(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _schema_errors(
    value: Any,
    schema: Mapping[str, Any],
    *,
    root: Mapping[str, Any] | None = None,
    at: str = "$",
) -> list[str]:
    """Narrow test-only port of the exact Hondō producer schema walker."""

    authority = schema if root is None else root
    reference = schema.get("$ref")
    if reference is not None:
        target: Any = authority
        for segment in reference[2:].split("/"):
            target = target[segment.replace("~1", "/").replace("~0", "~")]
        return _schema_errors(value, target, root=authority, at=at)

    errors: list[str] = []

    def valid_against(candidate: Mapping[str, Any]) -> bool:
        return not _schema_errors(value, candidate, root=authority, at=at)

    if "const" in schema and not _same_json_scalar(value, schema["const"]):
        errors.append(f"{at} does not equal its const")
    if "enum" in schema and not any(
        _same_json_scalar(value, item) for item in schema["enum"]
    ):
        errors.append(f"{at} is not in its enum")
    if "oneOf" in schema:
        matches = sum(valid_against(candidate) for candidate in schema["oneOf"])
        if matches != 1:
            errors.append(f"{at} matches {matches} oneOf branches")
    if "not" in schema and valid_against(schema["not"]):
        errors.append(f"{at} matches forbidden schema")
    if "if" in schema:
        branch = schema.get("then") if valid_against(schema["if"]) else schema.get("else")
        if branch is not None:
            errors.extend(_schema_errors(value, branch, root=authority, at=at))
    for component in schema.get("allOf", []):
        errors.extend(_schema_errors(value, component, root=authority, at=at))

    is_object = type(value) is dict
    if schema.get("type") == "object" and not is_object:
        return errors + [f"{at} is not an object"]
    if is_object:
        if schema.get("type") not in {None, "object"}:
            return errors + [f"{at} is not an object"]
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{at}.{key} is required")
        if schema.get("additionalProperties") is False:
            properties = schema.get("properties", {})
            for key in value:
                if key not in properties:
                    errors.append(f"{at}.{key} is not allowed")
        for key, property_schema in schema.get("properties", {}).items():
            if key in value:
                errors.extend(
                    _schema_errors(
                        value[key], property_schema, root=authority, at=f"{at}.{key}"
                    )
                )

    schema_type = schema.get("type")
    if schema_type == "array":
        if type(value) is not list:
            errors.append(f"{at} is not an array")
        else:
            if len(value) < schema.get("minItems", 0):
                errors.append(f"{at} has too few items")
            if len(value) > schema.get("maxItems", float("inf")):
                errors.append(f"{at} has too many items")
            for index, item in enumerate(value):
                errors.extend(
                    _schema_errors(
                        item, schema["items"], root=authority, at=f"{at}[{index}]"
                    )
                )
    elif schema_type == "string":
        if type(value) is not str:
            errors.append(f"{at} is not a string")
        else:
            if len(value) < schema.get("minLength", 0):
                errors.append(f"{at} is too short")
            if schema.get("pattern") and re.search(schema["pattern"], value) is None:
                errors.append(f"{at} does not match its pattern")
            if schema.get("format") == "date-time":
                try:
                    datetime.fromisoformat(value.replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    errors.append(f"{at} is not a date-time")
            if schema.get("format") == "uri":
                parsed = urlsplit(value)
                if not parsed.scheme or not parsed.netloc:
                    errors.append(f"{at} is not a URI")
    elif schema_type == "integer" and type(value) is not int:
        errors.append(f"{at} is not an integer")
    elif schema_type == "boolean" and type(value) is not bool:
        errors.append(f"{at} is not a boolean")

    if type(value) in {int, float}:
        if value < schema.get("minimum", float("-inf")):
            errors.append(f"{at} is below minimum")
        if value > schema.get("maximum", float("inf")):
            errors.append(f"{at} is above maximum")
    return errors


def _without_private_wire_fields(value: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(value))
    result.pop("claim_token", None)
    result.pop("manifest_url", None)
    return result


def test_verified_hondo_oracle_provenance_is_exact(
    oracle: dict[str, Any],
    submission_schema: dict[str, Any],
    result_schema: dict[str, Any],
) -> None:
    assert oracle["schema_version"] == (
        "ln_church.sdk_hondo_interoperability_fixture.v1"
    )
    provenance = oracle["provenance"]
    assert provenance["hondo_commit"] == HONDO_COMMIT
    assert provenance["hondo_tree"] == HONDO_TREE
    assert provenance["hondo_sole_parent"] == HONDO_PARENT
    assert provenance["schemas"] == {
        "submission": {
            "blob": SUBMISSION_SCHEMA_BLOB,
            "sha256": SUBMISSION_SCHEMA_SHA256,
        },
        "result": {
            "blob": RESULT_SCHEMA_BLOB,
            "sha256": RESULT_SCHEMA_SHA256,
        },
    }
    assert {
        item["blob"] for item in provenance["producers"].values()
    } == {PUBLIC_PRODUCER, LIFECYCLE_PRODUCER, NETWORK_PRODUCER}
    assert submission_schema["$id"].endswith(":submission")
    assert result_schema["$id"].endswith(":result")
    assert provenance["case_producers"]["completion_position"]["blob"] == (
        PUBLIC_PRODUCER
    )
    assert provenance["case_producers"]["status_lifecycle"]["blob"] == (
        LIFECYCLE_PRODUCER
    )
    journal_producer = provenance["case_producers"]["journal_reasonless"]
    assert journal_producer["blob"] == LIFECYCLE_PRODUCER
    assert journal_producer["tests"] == [
        "Claim token, wallet guard, snapshot, abandonment, expiry, and readiness stay separate",
        "new Completion commit binds raw bytes, canonical report, receipt, shard, work, event, and outbox without hot Offer counters",
        "Submission Status validates identity before I/O and dispatches only from a complete durable Task profile",
    ]


def test_sdk_consumes_exact_task_claim_and_five_readiness_outputs(
    oracle: dict[str, Any],
) -> None:
    outputs = oracle["public_outputs"]
    task_payload = outputs["task"]
    task = ScheduledHttpGetBatchTask.model_validate(task_payload)
    assert task.model_dump(mode="json", exclude_none=True) == task_payload
    for name in ("scheduled_at", "report_close_at"):
        assert WHOLE_SECOND_Z.fullmatch(task_payload[name])

    claim_payload = outputs["claim"]
    claim = ScheduledTaskClaimResponse.model_validate(claim_payload)
    assert claim._claim_token_value() == claim_payload["claim_token"]
    assert claim._manifest_url_value() == claim_payload["manifest_url"]
    assert claim.model_dump(mode="json", exclude_none=True) == (
        _without_private_wire_fields(claim_payload)
    )
    for name in (
        "claim_expires_at",
        "scheduled_at",
        "report_close_at",
        "manifest_url_not_before",
        "manifest_url_expires_at",
    ):
        assert WHOLE_SECOND_Z.fullmatch(claim_payload[name])

    readiness_outputs = outputs["readiness"]
    assert list(readiness_outputs) == [
        "pre_t_pending_establishment",
        "pre_t_preparing",
        "pre_t_ready",
        "post_t_ready",
        "post_t_unavailable",
    ]
    for name, payload in readiness_outputs.items():
        readiness = ScheduledTaskReadiness.model_validate(payload)
        assert readiness._manifest_url_value() == payload["manifest_url"]
        assert readiness.model_dump(mode="json", exclude_none=True) == (
            _without_private_wire_fields(payload)
        )
        if name.startswith("pre_t_"):
            assert set(payload) == {
                "schema_version",
                "task_id",
                "offer_status",
                "execution_available",
                "release_state",
                "manifest_url",
                "manifest_url_not_before",
                "manifest_url_expires_at",
                "retry_at",
            }
            assert "manifest_sha256" not in payload
        else:
            assert payload["manifest_sha256"] == "b" * 64
            assert "retry_at" not in payload
            assert "manifest_url_not_before" not in payload
    assert readiness_outputs["post_t_ready"]["execution_available"] is True
    assert readiness_outputs["post_t_ready"]["release_state"] == "READY"
    assert readiness_outputs["post_t_unavailable"]["execution_available"] is False
    assert readiness_outputs["post_t_unavailable"]["release_state"] == "UNAVAILABLE"


def test_sdk_consumes_exact_durable_receipt_and_status_lifecycle(
    oracle: dict[str, Any], result_schema: dict[str, Any]
) -> None:
    outputs = oracle["public_outputs"]
    receipt_payload = outputs["completion_receipt"]
    receipt = ScheduledCompletionReceipt.model_validate(receipt_payload)
    assert receipt.model_dump(mode="json") == receipt_payload
    assert WHOLE_SECOND_Z.fullmatch(receipt.accepted_at)

    lifecycle = outputs["status_lifecycle"]
    assert list(lifecycle) == [
        "pending",
        "blocked",
        "approved_base_due",
        "base_confirming",
        "base_paid_reference_pending",
        "reference_candidate_pending",
        "reference_awarded_bonus_due",
        "reference_bonus_confirming",
        "terminal_paid",
        "rejected_no_award",
    ]
    for payload in lifecycle.values():
        assert _schema_errors(payload, result_schema) == []
        status = ScheduledRewardStatus.model_validate(payload)
        assert status.model_dump(mode="json", exclude_none=True) == payload
        assert WHOLE_SECOND_Z.fullmatch(status.accepted_at)

    pending = lifecycle["pending"]
    assert pending["evaluation"] == {"state": "PENDING"}
    assert "reason" not in pending["evaluation"]
    assert lifecycle["approved_base_due"]["base_reward"] == {
        "entitlement_state": "DUE",
        "settlement_state": "DUE",
    }
    assert lifecycle["base_confirming"]["base_reward"] == {
        "entitlement_state": "DUE",
        "settlement_state": "CONFIRMING",
    }
    base_paid = lifecycle["base_paid_reference_pending"]
    assert base_paid["base_reward"]["settlement_state"] == "PAID_CONFIRMED"
    assert base_paid["reference_bonus"]["decision_state"] == "PENDING"
    assert base_paid["terminal"] is False
    terminal = lifecycle["terminal_paid"]
    assert terminal["base_reward"]["settlement_state"] == "PAID_CONFIRMED"
    assert terminal["reference_bonus"]["settlement_state"] == "PAID_CONFIRMED"
    assert terminal["terminal"] is True
    assert terminal["retry_after_seconds"] == 0


@pytest.mark.parametrize("reason", [None, "", "x" * 129])
def test_present_reason_remains_bounded_nonempty(
    oracle: dict[str, Any], reason: Any
) -> None:
    payload = copy.deepcopy(oracle["public_outputs"]["status_lifecycle"]["pending"])
    payload["evaluation"]["reason"] = reason
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(payload)


def test_status_models_reject_unknown_fields_and_enforce_exact_retry_matrix(
    oracle: dict[str, Any], result_schema: dict[str, Any]
) -> None:
    lifecycle = oracle["public_outputs"]["status_lifecycle"]
    unknown = copy.deepcopy(lifecycle["pending"])
    unknown["evaluation"]["unexpected"] = True
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(unknown)

    nonterminal_zero = copy.deepcopy(lifecycle["pending"])
    nonterminal_zero["retry_after_seconds"] = 0
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(nonterminal_zero)
    assert _schema_errors(nonterminal_zero, result_schema)

    terminal_retry = copy.deepcopy(lifecycle["terminal_paid"])
    terminal_retry["retry_after_seconds"] = 1
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(terminal_retry)
    assert _schema_errors(terminal_retry, result_schema)

    upper_bound = copy.deepcopy(lifecycle["pending"])
    upper_bound["retry_after_seconds"] = 3600
    assert _schema_errors(upper_bound, result_schema) == []
    assert ScheduledRewardStatus.model_validate(upper_bound).retry_after_seconds == 3600
    above_bound = copy.deepcopy(upper_bound)
    above_bound["retry_after_seconds"] = 3601
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(above_bound)
    assert _schema_errors(above_bound, result_schema)

    missing_award_settlement = copy.deepcopy(
        lifecycle["reference_awarded_bonus_due"]
    )
    del missing_award_settlement["reference_bonus"]["settlement_state"]
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(missing_award_settlement)
    pending_with_settlement = copy.deepcopy(lifecycle["pending"])
    pending_with_settlement["reference_bonus"]["settlement_state"] = "DUE"
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(pending_with_settlement)


def test_real_sdk_polling_continues_until_base_and_bonus_are_terminal(
    oracle: dict[str, Any]
) -> None:
    lifecycle = oracle["public_outputs"]["status_lifecycle"]
    sequence = [
        lifecycle[name]
        for name in (
            "pending",
            "approved_base_due",
            "base_confirming",
            "base_paid_reference_pending",
            "reference_candidate_pending",
            "reference_awarded_bonus_due",
            "reference_bonus_confirming",
            "terminal_paid",
        )
    ]
    expected_path = (
        "/api/agent/tasks/task_v18_status/submissions/"
        "sub_44444444444444444444444444444444/status"
    )
    calls: list[str] = []

    def exchange(method, path, query, headers, body):
        assert method == "GET"
        assert path == expected_path
        assert query is None
        assert body == b""
        assert "X-LN-Task-Claim-Token" not in headers
        calls.append(path)
        return TaskV2RawResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=json.dumps(sequence[len(calls) - 1], separators=(",", ":")).encode(
                "utf-8"
            ),
        )

    elapsed = [0.0]
    sleeps: list[float] = []

    def monotonic() -> float:
        return elapsed[0]

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        elapsed[0] += delay

    transport = TaskV2Transport(exchange=exchange)
    client = AgentTaskV2Client(
        transport=transport,
        monotonic=monotonic,
        sleep=sleep,
    )
    status = client.wait_for_submission_status(
        "task_v18_status",
        "sub_44444444444444444444444444444444",
        timeout_seconds=300,
        max_attempts=len(sequence),
    )
    assert status.model_dump(mode="json", exclude_none=True) == sequence[-1]
    assert len(calls) == len(sequence)
    assert sleeps == [15.0] * (len(sequence) - 1)


def test_sdk_generated_position_completion_matches_schema_and_hondo_runtime(
    oracle: dict[str, Any], submission_schema: dict[str, Any]
) -> None:
    payload = oracle["public_outputs"]["position_completion"]
    report = ScheduledCompletionReport(
        submission_id=payload["submission_id"],
        task_definition_digest=payload["task_definition_digest"],
        manifest_sha256=payload["manifest_sha256"],
        manifest_fetch=ManifestFetchResult(**payload["manifest_fetch"]),
        results=[ScheduledTargetResult(**item) for item in payload["results"]],
        completed_at=payload["completed_at"],
    )
    generated = report.model_dump(mode="json", exclude_none=True)
    assert generated == payload
    assert json.loads(report.canonical_bytes()) == payload
    assert _schema_errors(generated, submission_schema) == []
    assert generated["results"][0]["position"] == 0
    assert "target_position" not in report.canonical_bytes().decode("utf-8")
    assert oracle["provenance"]["case_producers"]["completion_position"] == {
        "blob": PUBLIC_PRODUCER,
        "test": "public Completion schema and runtime share the sole position field",
    }

    rejected = oracle["rejection_evidence"]["target_position_completion"]
    errors = _schema_errors(rejected, submission_schema)
    assert any("position is required" in item for item in errors)
    assert any("target_position is not allowed" in item for item in errors)
    assert oracle["rejection_evidence"]["runtime_error_code"] == (
        "report_binding_invalid"
    )
    with pytest.raises(ValidationError):
        ScheduledCompletionReport.model_validate(rejected)


def test_completion_nested_serializers_omit_only_optional_none() -> None:
    manifest_failure = ManifestFetchResult(
        outcome="release_timeout",
        observed_sha256=None,
        http_status=None,
        elapsed_ms=None,
    )
    target_failure = ScheduledTargetResult(
        position=0,
        target_url="https://target.example/a",
        outcome="timeout",
        http_status=None,
        elapsed_ms=None,
    )
    assert manifest_failure.model_dump(mode="json") == {
        "outcome": "release_timeout"
    }
    assert json.loads(manifest_failure.model_dump_json()) == {
        "outcome": "release_timeout"
    }
    assert target_failure.model_dump(mode="json") == {
        "position": 0,
        "target_url": "https://target.example/a",
        "outcome": "timeout",
    }
    assert json.loads(target_failure.model_dump_json()) == {
        "position": 0,
        "target_url": "https://target.example/a",
        "outcome": "timeout",
    }


def test_exact_reference_body_outputs_are_retained_without_body_bytes(
    oracle: dict[str, Any]
) -> None:
    outputs = oracle["reference_outputs"]
    assert [value["status"] for value in outputs.values()] == [200, 404, 500]
    assert [value["content_length"] for value in outputs.values()] == [
        "18",
        None,
        "18",
    ]
    for value in outputs.values():
        assert value["body_property_present"] is False
        assert value["body_bytes_property_present"] is False
        assert value["serialized_body_contains_source"] is False


def test_reasonless_oracle_status_persists_and_recovers_without_synthesis(
    oracle: dict[str, Any], tmp_path: Path
) -> None:
    case = oracle["public_outputs"]["journal_reasonless"]
    report_payload = case["completion_report"]
    receipt_payload = case["completion_receipt"]
    status_payload = case["pending_status"]
    report = ScheduledCompletionReport.model_validate(report_payload)
    # Preserve the exact producer payload for this journal-only proof.  The
    # separate position test exercises SDK report generation and schema
    # acceptance; this path must bind the original Hondō bytes unchanged.
    report_bytes = canonical_completion_bytes(report_payload)
    receipt = ScheduledCompletionReceipt.model_validate(receipt_payload)
    status = ScheduledRewardStatus.model_validate(status_payload)

    assert report.model_dump(mode="json", exclude_none=True) == report_payload
    assert report.canonical_bytes() == report_bytes
    assert report.canonical_digest() == receipt_payload["report_sha256"]
    assert receipt.model_dump(mode="json", exclude_none=True) == receipt_payload
    assert status.model_dump(mode="json", exclude_none=True) == status_payload
    assert hashlib.sha256(report_bytes).hexdigest() == receipt.report_sha256
    assert receipt.report_sha256 == status.report_sha256
    for name in (
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
        assert getattr(receipt, name) == getattr(status, name)
    assert status_payload["evaluation"] == {"state": "PENDING"}

    handle = "cred_" + "a" * 64
    journal = TaskJournal(
        tmp_path / "reasonless.journal",
        task_id=status.task_id,
        local_claim_credential_handle=handle,
        task_type=status.task_type,
        task_definition_version=status.task_definition_version,
        task_definition_digest=status.task_definition_digest,
    )
    journal.create()
    journal.mark_offer_rechecked(status.manifest_sha256)
    journal.start_manifest_attempt()
    journal.freeze_report(
        report_bytes,
        submission_id=status.submission_id,
        manifest_fetch_outcome=report.manifest_fetch.outcome,
    )
    journal.mark_completion_dispatch_attempted()
    snapshot = journal.mark_compound_completion_acked(
        ScheduledCompletionAcknowledgement(source="status", status=status)
    )
    assert snapshot.state == "COMPOUND_COMPLETION_ACKED"
    assert journal.compound_acknowledgement_facts()["source"] == "status"

    raw_journal = journal.path.read_text(encoding="utf-8")
    assert '"reason"' not in raw_journal
    recovered = TaskJournal(
        journal.path,
        task_id=status.task_id,
        local_claim_credential_handle=handle,
        task_type=status.task_type,
        task_definition_version=status.task_definition_version,
        task_definition_digest=status.task_definition_digest,
    ).load()
    assert recovered.state == "COMPOUND_COMPLETION_ACKED"
    assert recovered.payload["compound_ack"]["source"] == "status"


def test_real_client_posts_exact_sparse_hondo_completion_and_binds_receipt(
    oracle: dict[str, Any], submission_schema: dict[str, Any], tmp_path: Path
) -> None:
    outputs = oracle["public_outputs"]
    case = outputs["journal_reasonless"]
    report_payload = case["completion_report"]
    receipt_payload = case["completion_receipt"]
    report = ScheduledCompletionReport.model_validate(report_payload)
    report_bytes = canonical_completion_bytes(report_payload)
    assert report.model_dump(mode="json") == report_payload
    assert report.canonical_bytes() == report_bytes
    assert _schema_errors(json.loads(report_bytes), submission_schema) == []
    assert b'"http_status":null' not in report_bytes
    assert b'"observed_sha256":null' not in report_bytes

    claim = ScheduledTaskClaimResponse.model_validate(outputs["claim"])
    credential = claim.to_credential(agent_id="agent_hondo_interop")
    journal = TaskJournal(
        tmp_path / "real-client.journal",
        task_id=credential.task_id,
        local_claim_credential_handle=credential.local_claim_credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    journal.create()
    journal.mark_offer_rechecked(report.manifest_sha256)
    journal.start_manifest_attempt()
    journal.freeze_report(
        report_bytes,
        submission_id=report.submission_id,
        manifest_fetch_outcome=report.manifest_fetch.outcome,
    )

    calls: list[tuple[str, str, bytes]] = []

    def exchange(method, path, query, headers, body):
        assert query is None
        assert headers["X-LN-Task-Claim-Token"] == outputs["claim"]["claim_token"]
        assert headers["Idempotency-Key"] == report.submission_id
        assert method == "POST"
        assert path == "/api/agent/tasks/task_v18_test/completion"
        assert body == report_bytes
        assert _schema_errors(json.loads(body), submission_schema) == []
        calls.append((method, path, bytes(body)))
        return TaskV2RawResponse(
            status_code=202,
            headers={"content-type": "application/json"},
            body=json.dumps(
                receipt_payload, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8"),
        )

    client = AgentTaskV2Client(
        transport=TaskV2Transport(exchange=exchange),
        utcnow=lambda: datetime(2026, 8, 20, 3, 5, tzinfo=timezone.utc),
    )
    acknowledgement = client.complete_task(
        credential, report, journal=journal
    )
    assert acknowledgement.source == "receipt"
    assert acknowledgement.receipt is not None
    assert acknowledgement.receipt.model_dump(mode="json") == receipt_payload
    assert calls == [
        (
            "POST",
            "/api/agent/tasks/task_v18_test/completion",
            report_bytes,
        )
    ]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"
