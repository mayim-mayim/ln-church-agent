import json

import pytest

from ln_church_agent.task_v2_contract import (
    CLAIM_TOKEN_HEADER,
    IDEMPOTENCY_KEY_HEADER,
    TASK_DETAIL_QUERY,
    TASK_LIST_QUERY,
)
from ln_church_agent.task_v2_transport import (
    ClaimOutcomeUnknownError,
    CompletionOutcomeUnknownError,
    TaskV2APIError,
    TaskV2RawResponse,
    TaskV2Transport,
    TaskV2TransportError,
)


TOKEN = "A" * 43
SUBMISSION = "sub_" + "b" * 32


def _response(status, payload, headers=None):
    return TaskV2RawResponse(
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=json.dumps(payload, separators=(",", ":")).encode(),
    )


def _nested_error(code, retryable=False):
    return {
        "schema_version": "ln_church.agent_task_error.v1",
        "error": {
            "code": code,
            "message": "Safe error.",
            "request_id": "req_1",
            "retryable": retryable,
        },
    }


def test_list_and_detail_use_explicit_v2_profile_queries_only():
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, query, dict(headers), body))
        return _response(200, {"ok": True})

    transport = TaskV2Transport(exchange=exchange)
    assert transport.list_tasks() == {"ok": True}
    assert transport.get_task("task_1") == {"ok": True}
    assert calls[0][0:3] == ("GET", "/api/agent/tasks", TASK_LIST_QUERY)
    assert calls[1][0:3] == (
        "GET",
        "/api/agent/tasks/task_1",
        TASK_DETAIL_QUERY,
    )
    assert CLAIM_TOKEN_HEADER not in calls[0][3]


def test_claim_has_exactly_one_attempt_and_ambiguous_send_is_typed():
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path))
        raise TaskV2TransportError(
            "TASK_V2_TIMEOUT", request_bytes_sent=True, retryable=True
        )

    transport = TaskV2Transport(exchange=exchange)
    with pytest.raises(ClaimOutcomeUnknownError) as caught:
        transport.claim_task("task_1", b"{}")
    assert caught.value.code == "CLAIM_OUTCOME_UNKNOWN"
    assert calls == [("POST", "/api/agent/tasks/task_1/claim")]


def test_known_v2_error_is_nested_and_unknown_task_is_flat_v1_exception():
    responses = [
        _response(401, _nested_error("invalid_claim_token")),
        _response(404, {"error_code": "not_found"}),
    ]

    def exchange(method, path, query, headers, body):
        return responses.pop(0)

    transport = TaskV2Transport(exchange=exchange)
    with pytest.raises(TaskV2APIError) as known:
        transport.get_readiness("task_1", TOKEN)
    assert known.value.public_error_code == "invalid_claim_token"
    assert known.value.status_code == 401

    with pytest.raises(TaskV2APIError) as unknown:
        transport.get_task("missing")
    assert unknown.value.public_error_code == "not_found"
    assert unknown.value.status_code == 404


def test_invalid_flat_error_for_known_profile_is_rejected():
    transport = TaskV2Transport(
        exchange=lambda *args: _response(
            401, {"error_code": "invalid_claim_token"}
        )
    )
    with pytest.raises(TaskV2TransportError) as caught:
        transport.get_readiness("task_1", TOKEN)
    assert caught.value.code == "TASK_V2_RESPONSE_INVALID"


def test_status_is_tokenless_and_completion_headers_bind_same_submission():
    calls = []

    def exchange(method, path, query, headers, body):
        calls.append((method, path, dict(headers), body))
        return _response(202 if method == "POST" else 200, {"ok": True})

    transport = TaskV2Transport(exchange=exchange)
    assert transport.get_submission_status("task_1", SUBMISSION) == {"ok": True}
    assert CLAIM_TOKEN_HEADER not in calls[0][2]

    assert transport.post_completion_bytes(
        "task_1", TOKEN, SUBMISSION, b"{}"
    ) == {"ok": True}
    assert calls[1][2][CLAIM_TOKEN_HEADER] == TOKEN
    assert calls[1][2][IDEMPOTENCY_KEY_HEADER] == SUBMISSION
    assert calls[1][3] == b"{}"


def test_completion_requires_exact_202_receipt_status():
    transport = TaskV2Transport(
        exchange=lambda *args: _response(200, {"ok": True})
    )
    with pytest.raises(CompletionOutcomeUnknownError):
        transport.post_completion_bytes("task_1", TOKEN, SUBMISSION, b"{}")


def test_public_get_honors_retry_after_with_bounded_retry():
    sleeps = []
    responses = [
        _response(
            503,
            _nested_error("temporarily_unavailable", retryable=True),
            headers={"Retry-After": "2"},
        ),
        _response(200, {"ok": True}),
    ]
    transport = TaskV2Transport(
        exchange=lambda *args: responses.pop(0), sleep=sleeps.append
    )
    assert transport.list_tasks() == {"ok": True}
    assert sleeps == [2.0]


def test_errors_do_not_retain_remote_message_or_secret_values():
    secret = "secret-signed-query-value"
    payload = _nested_error("invalid_claim_token")
    payload["error"]["message"] = secret
    transport = TaskV2Transport(exchange=lambda *args: _response(401, payload))
    with pytest.raises(TaskV2APIError) as caught:
        transport.get_readiness("task_1", TOKEN)
    rendered = repr(caught.value) + str(caught.value) + repr(caught.value.__dict__)
    assert secret not in rendered
    assert TOKEN not in rendered
