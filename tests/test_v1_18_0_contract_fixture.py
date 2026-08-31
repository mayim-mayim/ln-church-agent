import ast
import hashlib
import json
from pathlib import Path

import pytest

from ln_church_agent.task_journal import JournalError, TaskJournal


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    ROOT
    / "ln_church_agent"
    / "contracts"
    / "v18-scheduled-http-get-batch-contract-v1.json"
)
FIXTURE_SHA256 = (
    "09eb478e30b56fec6efb462cfb43733b1e907bb247943f8fe6336af73d362785"
)


def _fixture():
    data = FIXTURE_PATH.read_bytes()
    return data, json.loads(data)


def _setup_keyword(name):
    tree = ast.parse((ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg == name:
                return ast.literal_eval(keyword.value)
    raise AssertionError("setup.py is missing setup(%s=...)" % name)


def test_canonical_fixture_bytes_hash_json_and_final_lf():
    data, fixture = _fixture()
    assert data.startswith(b"{\n")
    assert data.endswith(b"\n")
    assert not data.endswith(b"\n\n")
    assert b"\r\n" not in data
    assert hashlib.sha256(data).hexdigest() == FIXTURE_SHA256
    assert fixture["contract_id"] == (
        "ln_church.v18.scheduled_http_get_batch"
    )
    assert fixture["contract_version"] == "1.0.0"
    assert fixture["target_release"] == "v1.18.0"
    assert fixture["task_type"] == "scheduled_http_get_batch.v1"
    assert fixture["task_definition_version"] == "1.0.0"
    assert fixture["public_task_schema_version"] == (
        "ln_church.agent_task.v2"
    )


def test_canonical_fixture_is_declared_as_contract_package_data():
    package_data = _setup_keyword("package_data")
    assert package_data == {
        "ln_church_agent": ["contracts/*.json"]
    }


def test_fixture_network_fetch_policy_leaves_are_exact():
    _, fixture = _fixture()
    policy = fixture["network_fetch_policy"]
    assert policy["applies_to"] == [
        "ORIGIN_ACTIVATION",
        "OFFICIAL_SDK_MANIFEST_RELEASE",
        "OFFICIAL_SDK_TARGET",
        "LN_CHURCH_REFERENCE",
    ]
    assert policy["fresh_a_and_aaaa_resolution_per_attempt"] is True
    assert (
        policy["reject_entire_answer_set_if_any_non_global_or_reserved"]
        is True
    )
    assert (
        policy["reject_ipv4_mapped_ipv6_for_non_global_or_reserved"]
        is True
    )
    assert policy["pin_one_vetted_numeric_peer_per_attempt"] is True
    assert policy["connected_peer_must_equal_pin"] is True
    assert (
        policy["tls_sni_certificate_and_host_use_canonical_hostname"]
        is True
    )
    assert policy["fallback_reresolution_within_attempt"] is False
    for key in (
        "ambient_proxy",
        "credential_forwarding",
        "cookie",
        "authorization",
        "proxy_authorization",
        "netrc",
        "ambient_session",
        "request_body",
        "requester_headers",
        "automatic_content_decoding",
    ):
        assert policy[key] is False
    assert policy["redirects"] == 0
    assert policy["accepted_content_encoding"] == "identity"
    assert policy["content_encoding_absent_means_identity"] is True
    assert policy["required_test_vectors_apply_to_each_scope"] is True
    assert policy["required_test_vectors"] == [
        "IPV4_RESERVED",
        "IPV6_RESERVED",
        "MIXED_VALID_INVALID_ANSWER_SET",
        "IPV4_MAPPED_IPV6",
        "DNS_REBINDING",
        "CONNECTED_PEER_MISMATCH",
        "TLS_CANONICAL_HOST_SNI_CERTIFICATE_AND_HOST",
        "TLS_HOSTNAME_MISMATCH",
        "REDIRECT",
        "PROXY_ENVIRONMENT",
        "OVERSIZED_HEADERS_BODY",
        "SLOW_HEAD_BODY",
        "UNSUPPORTED_ENCODING",
        "NON_200_RETRYABLE_STATUS_WITH_UNSUPPORTED_ENCODING",
        "COOKIE_JAR",
        "DEFAULT_AUTHORIZATION",
        "PROXY_AUTHORIZATION",
        "NETRC",
        "CHUNKED_BODY_OVERFLOW",
        "FALSE_CONTENT_LENGTH",
        "SIGNED_QUERY_LOG_REDACTION",
    ]
    sdk_owned_scopes = [
        scope
        for scope in policy["applies_to"]
        if scope
        in {
            "OFFICIAL_SDK_MANIFEST_RELEASE",
            "OFFICIAL_SDK_TARGET",
        }
    ]
    assert sdk_owned_scopes == [
        "OFFICIAL_SDK_MANIFEST_RELEASE",
        "OFFICIAL_SDK_TARGET",
    ]
    assert len(policy["required_test_vectors"]) * len(sdk_owned_scopes) == 42
    assert "ORIGIN_ACTIVATION" not in sdk_owned_scopes
    assert "LN_CHURCH_REFERENCE" not in sdk_owned_scopes


def test_fixture_claim_readiness_and_error_dispatch_leaves_are_exact():
    _, fixture = _fixture()
    claim = fixture["claim"]
    assert claim["request_schema_version"] == (
        "ln_church.agent_task_claim_request.v1"
    )
    assert claim["response_schema_version"] == (
        "ln_church.agent_task_claim_response.v2"
    )
    assert claim["transport_attempts"] == 1
    assert claim["ambiguity_state"] == "CLAIM_OUTCOME_UNKNOWN"
    assert claim["claim_response_includes_opaque_signed_manifest_url"] is True
    assert claim["claim_response_includes_manifest_digest_before_t"] is False
    assert claim["readiness_schema_version"] == (
        "ln_church.agent_task_readiness.v1"
    )
    assert claim["readiness_is_canonical_immediate_t_time_status_check"] is True
    assert (
        claim[
            "readiness_at_or_after_t_includes_expected_digest_when_projection_unavailable"
        ]
        is True
    )
    assert claim["token_transport"] == "X-LN-Task-Claim-Token_HEADER"
    assert claim["token_encoding"] == (
        "43_CHAR_UNPADDED_BASE64URL_OF_32_BYTES"
    )
    assert claim["abandonment"]["schema_version"] == (
        "ln_church.agent_task_claim_abandon_request.v1"
    )
    assert claim["abandonment"]["idempotency_field"] == "abandonment_id"
    assert claim["expiry"][
        "at_report_close_for_unsubmitted_claimed_execution"
    ] is True

    assert fixture["error_schema_version"] == (
        "ln_church.agent_task_error.v1"
    )
    dispatch = fixture["error_envelope_dispatch"]
    assert dispatch["scheduled_http_get_batch_v2_profile"] == (
        "NESTED_LN_CHURCH_AGENT_TASK_ERROR_V1"
    )
    assert dispatch["released_v1_strict_profile"] == (
        "PRESERVE_EXACT_FLAT_ERROR_CODE_AND_LEGACY_CODES"
    )
    assert dispatch["unresolved_task_profile_including_unknown_task_id"] == (
        "RELEASED_FLAT_V1_ERROR_ENVELOPE"
    )
    assert dispatch["v2_sdk_accepts_pre_profile_flat_v1_exception"] is True


def test_fixture_completion_and_sdk_recovery_leaves_are_exact():
    _, fixture = _fixture()
    completion = fixture["completion_report"]
    assert completion["public_operation"] == (
        "ATOMIC_TASK_REPORT_AND_GENERIC_COMPLETION"
    )
    assert completion["schema_version"] == (
        "ln_church.scheduled_http_get_batch_completion.v1"
    )
    assert completion["receipt_schema_version"] == (
        "ln_church.agent_task_completion_receipt.v2"
    )
    assert completion["status_schema_version"] == (
        "ln_church.agent_task_reward_status.v2"
    )
    assert completion["maximum_utf8_bytes"] == 65536
    assert completion["canonicalization"] == "RFC8785_JCS"
    assert completion["digest"] == "SHA256_LOWERCASE_HEX"
    assert completion["idempotency_key_header_must_equal_submission_id"] is True
    assert completion["same_id_same_body"] == "RETURN_SAME_RECEIPT"
    assert completion["same_id_changed_body"] == "SUBMISSION_CONFLICT"
    assert completion["target_order_and_coverage"] == {
        "manifest_fetch_retrieved": "EXACT_MANIFEST_LIST",
        "manifest_fetch_not_retrieved": "EMPTY_RESULTS",
    }
    assert completion["target_outcomes"] == [
        "http_response",
        "dns_error",
        "tls_error",
        "connection_error",
        "timeout",
        "protocol_error",
        "interrupted_indeterminate",
        "not_attempted_interrupted",
        "not_attempted_deadline",
    ]

    sdk = fixture["sdk"]
    assert sdk["journal_key"] == [
        "task_id",
        "local_claim_credential_handle",
    ]
    assert sdk["journal_irreversible_binding_at_t"] == "manifest_sha256"
    assert sdk["public_execution_id"] is False
    assert sdk["manifest_fetch_maximum_attempts"] == 3
    assert sdk["manifest_fetch_operation_deadline_ms"] == 5000
    assert sdk["manifest_fetch_connect_timeout_ms"] == 500
    assert sdk["manifest_fetch_response_head_timeout_ms"] == 1200
    assert sdk["manifest_fetch_total_timeout_per_attempt_ms"] == 1500
    assert sdk["manifest_fetch_next_attempt_requires_full_timeout_remaining"] is True
    assert sdk["manifest_fetch_also_ends_at_report_close"] is True
    assert sdk["target_retry"] is False
    assert sdk["write_attempt_started_before_dispatch"] is True
    assert sdk["resend_indeterminate_target"] is False
    assert sdk["journal_failure_behavior"] == "FAIL_CLOSED_NO_MORE_TARGET_GET"
    assert sdk["recursive_checkpoint"] is False
    assert sdk["completion_retry"] == (
        "STATUS_FIRST_THEN_SAME_ID_AND_BYTES_ONLY_IF_ABSENT_AND_BEFORE_CLOSE"
    )
    assert sdk["compound_completion_ack_state"] == (
        "COMPOUND_COMPLETION_ACKED"
    )
    assert sdk["separate_report_and_completion_ack_states"] is False
    assert sdk["existing_on_time_receipt_recoverable_after_close"] is True
    assert sdk["absent_receipt_retry_at_or_after_close"] is False
    assert sdk["manifest_fetch_exact_signed_url_reused_for_every_attempt"] is True
    assert sdk["manifest_fetch_signed_query_is_only_allowed_credential"] is True
    assert sdk["manifest_fetch_signed_query_sent_only_to_exact_url"] is True
    assert sdk["manifest_fetch_signed_query_forwarded"] is False
    assert sdk["manifest_fetch_signed_url_logged"] is False
    assert sdk["manifest_fetch_response_header_maximum_bytes"] == 32768
    assert sdk["manifest_fetch_http_200_body_maximum_bytes"] == 32768
    assert sdk["manifest_fetch_non_200_body_read_maximum_bytes"] == 0
    assert (
        sdk[
            "manifest_fetch_network_policy_or_response_boundary_violation_precedes_http_status_retry"
        ]
        is True
    )
    assert sdk[
        "manifest_fetch_non_200_retryable_status_with_unsupported_encoding_oracle"
    ] == "RELEASE_ENCODING_UNSUPPORTED_ATTEMPTS_1_BODY_BYTES_READ_0"


def test_fixture_at_t_binding_leaf_drives_durable_journal_oracle(tmp_path):
    _, fixture = _fixture()
    binding_field = fixture["sdk"]["journal_irreversible_binding_at_t"]
    assert binding_field == "manifest_sha256"

    claim_token = "A" * 43
    signed_manifest_url = (
        "https://tasks-release.mayim-mayim.com/manifests/binding.json"
        "?Signature=FIXTURE_BINDING_SECRET_SENTINEL"
    )
    local_handle = hashlib.sha256(
        (claim_token + "\x00" + signed_manifest_url).encode("utf-8")
    ).hexdigest()
    journal_path = tmp_path / "binding-journal.json"
    journal = TaskJournal(
        journal_path,
        task_id="task_fixture_binding",
        local_claim_credential_handle=local_handle,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest="d" * 64,
    )
    journal.create()

    readiness_digest = "b" * 64
    bound = journal.mark_offer_rechecked(readiness_digest)
    assert bound.state == "OFFER_RECHECKED"
    assert bound.payload[binding_field] == readiness_digest
    envelope = json.loads(journal_path.read_bytes())
    assert envelope["payload"][binding_field] == readiness_digest

    with pytest.raises(JournalError, match="JOURNAL_STATE_CONFLICT"):
        journal.mark_offer_rechecked("c" * 64)
    assert journal.load().payload[binding_field] == readiness_digest

    persisted = journal_path.read_text(encoding="utf-8")
    assert claim_token not in persisted
    assert signed_manifest_url not in persisted
    assert "FIXTURE_BINDING_SECRET_SENTINEL" not in persisted
