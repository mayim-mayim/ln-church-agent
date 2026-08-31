import hashlib
import json

import pytest

from ln_church_agent.task_v2_contract import (
    CONTRACT_FIXTURE_SHA256,
    ManifestContractError,
    TASK_DETAIL_QUERY,
    TASK_LIST_QUERY,
    load_contract_fixture_bytes,
    task_abandon_path,
    task_claim_path,
    task_completion_path,
    task_detail_path,
    task_readiness_path,
    task_status_path,
    validate_claim_token,
    validate_manifest_bytes,
)


def _manifest(urls=None):
    value = {
        "schema_version": "ln_church.http_get_batch_manifest.v1",
        "method": "GET",
        "urls": urls or ["https://example.com/a?mode=health"],
    }
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def test_packaged_fixture_is_exact_valid_final_lf_mirror():
    data = load_contract_fixture_bytes()
    assert data.endswith(b"\n")
    assert hashlib.sha256(data).hexdigest() == CONTRACT_FIXTURE_SHA256
    assert json.loads(data.decode("utf-8"))["task_type"] == (
        "scheduled_http_get_batch.v1"
    )


def test_v2_routes_and_profile_queries_are_exact_and_separate_from_v1():
    assert TASK_LIST_QUERY == (
        "task_type=scheduled_http_get_batch.v1"
        "&task_schema_version=ln_church.agent_task.v2"
    )
    assert TASK_DETAIL_QUERY == "task_schema_version=ln_church.agent_task.v2"
    assert task_detail_path("task_1") == "/api/agent/tasks/task_1"
    assert task_claim_path("task_1") == "/api/agent/tasks/task_1/claim"
    assert task_abandon_path("task_1") == "/api/agent/tasks/task_1/claim/abandon"
    assert task_readiness_path("task_1") == "/api/agent/tasks/task_1/readiness"
    assert task_completion_path("task_1") == "/api/agent/tasks/task_1/completion"
    assert task_status_path("task_1", "sub_" + "a" * 32) == (
        "/api/agent/tasks/task_1/submissions/sub_"
        + "a" * 32
        + "/status"
    )


def test_manifest_validation_preserves_exact_canonical_bytes_and_order():
    raw = _manifest(
        ["https://example.com/a", "https://example.com/b?mode=health"]
    )
    digest = hashlib.sha256(raw).hexdigest()
    result = validate_manifest_bytes(raw, digest)
    assert result.raw_bytes == raw
    assert result.sha256 == digest
    assert result.urls == (
        "https://example.com/a",
        "https://example.com/b?mode=health",
    )


@pytest.mark.parametrize(
    "urls",
    [
        ["http://example.com/a"],
        ["https://EXAMPLE.com/a"],
        ["https://example.com:443/a"],
        ["https://example.com"],
        ["https://example.com/a", "https://other.example/a"],
        ["https://example.com/a", "https://example.com/a"],
        ["https://127.0.0.1/a"],
        ["https://example.com/../a"],
        ["https://example.com/é"],
    ],
)
def test_manifest_rejects_noncanonical_or_non_same_origin_urls(urls):
    raw = _manifest(urls)
    with pytest.raises(ManifestContractError) as caught:
        validate_manifest_bytes(raw, hashlib.sha256(raw).hexdigest())
    assert caught.value.outcome == "release_schema_invalid"


def test_manifest_digest_is_server_pinned_and_checked_before_schema_use():
    raw = _manifest()
    with pytest.raises(ManifestContractError) as caught:
        validate_manifest_bytes(raw, "0" * 64)
    assert caught.value.outcome == "release_digest_mismatch"


def test_manifest_rejects_noncanonical_json_and_unknown_fields():
    value = {
        "schema_version": "ln_church.http_get_batch_manifest.v1",
        "method": "GET",
        "urls": ["https://example.com/a"],
        "extra": True,
    }
    raw = json.dumps(value, separators=(",", ":")).encode()
    with pytest.raises(ManifestContractError) as caught:
        validate_manifest_bytes(raw, hashlib.sha256(raw).hexdigest())
    assert caught.value.outcome == "release_schema_invalid"


def test_claim_token_requires_canonical_unpadded_base64url_of_32_bytes():
    assert validate_claim_token("A" * 43) == "A" * 43
    with pytest.raises(ValueError, match="^Invalid claim credential\\.$"):
        validate_claim_token("A" * 42 + "B")
