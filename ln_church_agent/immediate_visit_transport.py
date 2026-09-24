"""Route-closed, one-request transport for immediate visits; no lower retry."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import wraps
import time
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
from urllib.parse import urlencode

import httpx

from .task_transport import _WriteTracker, _new_pinned_httpx_transport, _resolve_addresses
from .network_fetch import _resolve_public_addresses
from .immediate_visit_contract import (
    PUBLIC_API_ORIGIN, PUBLIC_API_HOST, TASK_LIST_PATH, TASK_TYPE, TASK_SCHEMA_VERSION,
    CLAIM_TOKEN_HEADER, IDEMPOTENCY_KEY_HEADER, ERROR_SCHEMA_VERSION, ERROR_CODES_BY_STATUS,
    decode_json_object, positive_bound, validate_claim_token, validate_opaque_id,
    validate_submission_id, task_detail_path, task_claim_path, task_abandon_path,
    task_completion_path, task_status_path,
)

MAXIMUM_JSON_BYTES = 4 * 1024 * 1024  # bounded 100-Task page with ten 2-KiB endpoints each
MAXIMUM_RESPONSE_HEADER_BYTES = 32768
USER_AGENT = "ln-church-agent-immediate-visit/1.18.6"
_SAFE_CODES = frozenset({
    "TRANSPORT_CLOSED", "CLIENT_CLOSED", "REQUEST_INVALID", "RESPONSE_INVALID", "TIMEOUT",
    "TRANSPORT_ERROR", "DNS_POLICY_REJECTED", "RESPONSE_TOO_LARGE", "RESPONSE_ENCODING_REJECTED",
    "CREDENTIAL_INVALID", "REPORT_INVALID", "RESPONSE_BINDING_INVALID", "CLAIM_OUTCOME_UNKNOWN",
    "COMPLETION_OUTCOME_UNKNOWN", "API_ERROR",
})


class ImmediateVisitError(Exception):
    def __init__(self, code: str, *, status_code: Optional[int] = None,
                 request_bytes_sent: Optional[bool] = None) -> None:
        self.code = code if code in _SAFE_CODES else "TRANSPORT_ERROR"
        self.status_code = status_code if type(status_code) is int and 100 <= status_code <= 599 else None
        self.request_bytes_sent = request_bytes_sent if type(request_bytes_sent) is bool else None
        super().__init__(self.code)


class ImmediateVisitTransportError(ImmediateVisitError):
    pass


class ImmediateVisitAPIError(ImmediateVisitError):
    def __init__(self, public_error_code: str, *, status_code: int) -> None:
        self.public_error_code = (public_error_code if public_error_code in ERROR_CODES_BY_STATUS.get(status_code, ())
                                  else "invalid_response")
        super().__init__("API_ERROR", status_code=status_code, request_bytes_sent=True)


def _public_boundary(function: Any) -> Any:
    """Detach the full exception graph, including hidden JSON/body contexts."""
    @wraps(function)
    def call(*args: Any, **kwargs: Any) -> Any:
        detached = None
        try:
            return function(*args, **kwargs)
        except ImmediateVisitAPIError as error:
            detached = ImmediateVisitAPIError(error.public_error_code, status_code=error.status_code)
        except ImmediateVisitError as error:
            detached = ImmediateVisitTransportError(error.code, status_code=error.status_code,
                                                    request_bytes_sent=error.request_bytes_sent)
        except ValueError:
            detached = ValueError("Invalid immediate visit request.")
        if detached is not None:
            raise detached
    return call


@dataclass(frozen=True)
class ImmediateVisitRawResponse:
    status_code: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


Exchange = Callable[[str, str, Optional[str], Mapping[str, str], bytes, float], ImmediateVisitRawResponse]


class ImmediateVisitTransport:
    """Every method performs at most one HTTP request, including authenticated status."""

    def __init__(self, *, exchange: Optional[Exchange] = None,
                 resolver: Callable[[str, int], Sequence[str]] = _resolve_addresses,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if exchange is not None and not callable(exchange):
            raise ValueError("Invalid immediate visit exchange.")
        self._exchange = exchange or self._default_exchange
        self._resolver = resolver
        self._monotonic = monotonic
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> "ImmediateVisitTransport":
        if self._closed:
            raise ImmediateVisitTransportError("TRANSPORT_CLOSED")
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _default_exchange(self, method: str, path: str, query: Optional[str],
                          headers: Mapping[str, str], body: bytes,
                          timeout_seconds: float) -> ImmediateVisitRawResponse:
        tracker = _WriteTracker()
        transport = None
        deadline = self._monotonic() + timeout_seconds
        try:
            addresses = _resolve_public_addresses(PUBLIC_API_HOST, resolver=self._resolver,
                                                   timeout=min(5.0, timeout_seconds))
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=False)
            transport = _new_pinned_httpx_transport(addresses[0], tracker, deadline, self._monotonic)
            url = PUBLIC_API_ORIGIN + path + (("?" + query) if query is not None else "")
            timeout = httpx.Timeout(connect=min(5.0, remaining), read=min(10.0, remaining),
                                    write=min(10.0, remaining), pool=min(5.0, remaining))
            with httpx.Client(transport=transport, trust_env=False, follow_redirects=False,
                              cookies=None, timeout=timeout) as client:
                transport = None
                with client.stream(method, url, headers=dict(headers), content=body or None) as response:
                    header_bytes = sum(len(k.encode("latin-1")) + len(v.encode("latin-1")) + 4
                                       for k, v in response.headers.multi_items())
                    if header_bytes > MAXIMUM_RESPONSE_HEADER_BYTES:
                        raise ImmediateVisitTransportError("RESPONSE_TOO_LARGE", request_bytes_sent=tracker.request_bytes_sent)
                    encodings = response.headers.get_list("content-encoding")
                    if encodings and (len(encodings) != 1 or encodings[0].strip().lower() != "identity"):
                        raise ImmediateVisitTransportError("RESPONSE_ENCODING_REJECTED", request_bytes_sent=tracker.request_bytes_sent)
                    chunks = []
                    total = 0
                    for chunk in response.iter_raw():
                        if self._monotonic() >= deadline:
                            raise ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=tracker.request_bytes_sent)
                        total += len(chunk)
                        if total > MAXIMUM_JSON_BYTES:
                            raise ImmediateVisitTransportError("RESPONSE_TOO_LARGE", request_bytes_sent=tracker.request_bytes_sent)
                        chunks.append(bytes(chunk))
                    if self._monotonic() >= deadline:
                        raise ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=tracker.request_bytes_sent)
                    return ImmediateVisitRawResponse(response.status_code, dict(response.headers), b"".join(chunks))
        except ImmediateVisitError:
            raise
        except httpx.TimeoutException:
            raise ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=tracker.request_bytes_sent) from None
        except Exception:
            raise ImmediateVisitTransportError("TRANSPORT_ERROR", request_bytes_sent=tracker.request_bytes_sent) from None
        finally:
            if transport is not None:
                transport.close()

    @_public_boundary
    def _once(self, method: str, path: str, *, query: Optional[str] = None,
              claim_token: Optional[str] = None, idempotency_key: Optional[str] = None,
              body: bytes = b"", timeout_seconds: float = 20.0,
              expected_statuses: tuple = (200,)) -> Dict[str, Any]:
        positive_bound(timeout_seconds, "timeout_seconds")
        if self._closed:
            raise ImmediateVisitTransportError("TRANSPORT_CLOSED")
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": USER_AGENT}
        if claim_token is not None:
            headers[CLAIM_TOKEN_HEADER] = validate_claim_token(claim_token)
        if idempotency_key is not None:
            headers[IDEMPOTENCY_KEY_HEADER] = validate_opaque_id(idempotency_key, "idempotency_key")
        if body:
            headers["Content-Type"] = "application/json"
        try:
            raw = self._exchange(method, path, query, headers, body, float(timeout_seconds))
        except ImmediateVisitError:
            raise
        except Exception:
            raise ImmediateVisitTransportError("TRANSPORT_ERROR", request_bytes_sent=None) from None
        if not isinstance(raw, ImmediateVisitRawResponse) or type(raw.status_code) is not int:
            raise ImmediateVisitTransportError("RESPONSE_INVALID", request_bytes_sent=True)
        status = raw.status_code
        try:
            if not isinstance(raw.headers, Mapping) or sum(len(str(k)) + len(str(v)) + 4 for k, v in raw.headers.items()) > MAXIMUM_RESPONSE_HEADER_BYTES:
                raise ValueError
            encodings = [v for k, v in raw.headers.items() if str(k).lower() == "content-encoding"]
            if encodings and (len(encodings) != 1 or str(encodings[0]).strip().lower() != "identity"):
                raise ValueError
            payload = decode_json_object(raw.body, MAXIMUM_JSON_BYTES)
        except Exception:
            raise ImmediateVisitTransportError("RESPONSE_INVALID", request_bytes_sent=True) from None
        if status in expected_statuses:
            return payload
        if 200 <= status <= 299:
            raise ImmediateVisitTransportError("RESPONSE_INVALID", request_bytes_sent=True)
        if (set(payload) == {"schema_version", "code", "message", "request_id"}
                and payload.get("schema_version") == ERROR_SCHEMA_VERSION
                and payload.get("code") in ERROR_CODES_BY_STATUS.get(status, ())
                and isinstance(payload.get("message"), str) and isinstance(payload.get("request_id"), str)):
            code = payload["code"]
            payload.clear()
            raise ImmediateVisitAPIError(code, status_code=status)
        payload.clear()
        raise ImmediateVisitTransportError("RESPONSE_INVALID", status_code=status, request_bytes_sent=True)

    def list_tasks(self, *, limit: int = 25, cursor: Optional[str] = None, timeout_seconds: float = 20.0) -> Dict[str, Any]:
        positive_bound(limit, "limit", integer=True, maximum=100)
        query = {"task_type": TASK_TYPE, "task_schema_version": TASK_SCHEMA_VERSION, "limit": str(limit)}
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor or len(cursor.encode("utf-8")) > 8192:
                raise ValueError("Invalid cursor.")
            query["cursor"] = cursor
        return self._once("GET", TASK_LIST_PATH, query=urlencode(query), timeout_seconds=timeout_seconds)

    def get_task(self, task_id: str, *, timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("GET", task_detail_path(task_id), timeout_seconds=timeout_seconds)

    def claim_task(self, task_id: str, body: bytes, *, idempotency_key: str,
                   timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("POST", task_claim_path(task_id), body=body, idempotency_key=idempotency_key,
                          timeout_seconds=timeout_seconds)

    def abandon_claim(self, task_id: str, claim_token: str, body: bytes, *, idempotency_key: str,
                      timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("POST", task_abandon_path(task_id), claim_token=claim_token,
                          idempotency_key=idempotency_key, body=body, timeout_seconds=timeout_seconds)

    def post_completion_bytes(self, task_id: str, claim_token: str, submission_id: str, body: bytes,
                              *, timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("POST", task_completion_path(task_id), claim_token=claim_token,
                          idempotency_key=validate_submission_id(submission_id), body=body,
                          timeout_seconds=timeout_seconds, expected_statuses=(200, 202))

    def get_submission_status(self, task_id: str, submission_id: str, claim_token: str,
                              *, timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("GET", task_status_path(task_id, submission_id), claim_token=claim_token,
                          timeout_seconds=timeout_seconds)
