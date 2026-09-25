"""Finite, secret-safe transport for the parallel v1.18 Task profile."""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import json
import math
import random
import time
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

import httpx
from pydantic import ValidationError

from .task_transport import (
    _WriteTracker,
    _address_is_public_unicast,
    _new_pinned_httpx_transport,
    _resolve_addresses,
)
from .task_v2_contract import (
    CLAIM_TOKEN_HEADER,
    IDEMPOTENCY_KEY_HEADER,
    PUBLIC_API_HOST,
    PUBLIC_API_ORIGIN,
    TASK_DETAIL_QUERY,
    TASK_LIST_PATH,
    TASK_LIST_QUERY,
    V2_ERROR_CODES_BY_STATUS,
    decode_json_object,
    task_abandon_path,
    task_claim_path,
    task_completion_path,
    task_detail_path,
    task_readiness_path,
    task_status_path,
    validate_claim_token,
    validate_submission_id,
    validate_task_id,
)
from .task_v2_models import ScheduledTaskErrorResponse


TASK_V2_USER_AGENT = "ln-church-agent-task-v2/1.18.7"
TASK_V2_MAXIMUM_JSON_BYTES = 256 * 1024
TASK_V2_MAXIMUM_RESPONSE_HEADER_BYTES = 32768
_RETRYABLE_GET_STATUSES = frozenset({429, 500, 502, 503, 504})
_PUBLIC_GET_BACKOFF = (0.25, 0.5)


class TaskV2Error(Exception):
    """Finite base error which never retains a URL, body, or credential."""

    def __init__(
        self,
        code: str,
        *,
        status_code: Optional[int] = None,
        retry_after_seconds: Optional[float] = None,
        request_bytes_sent: Optional[bool] = None,
        retryable: bool = False,
    ) -> None:
        if not isinstance(code, str) or not code or len(code) > 64:
            code = "TASK_V2_TRANSPORT_ERROR"
        if type(status_code) is not int or not 100 <= status_code <= 599:
            status_code = None
        retry_after_seconds = _finite_retry_after(retry_after_seconds)
        if request_bytes_sent not in (True, False, None):
            request_bytes_sent = None
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds
        self.request_bytes_sent = request_bytes_sent
        self.retryable = bool(retryable)


class TaskV2TransportError(TaskV2Error):
    pass


class TaskV2APIError(TaskV2Error):
    def __init__(
        self,
        public_error_code: str,
        *,
        status_code: int,
        retry_after_seconds: Optional[float] = None,
        retryable: bool = False,
    ) -> None:
        allowed = V2_ERROR_CODES_BY_STATUS.get(status_code, frozenset())
        if public_error_code not in allowed:
            public_error_code = "invalid_response"
            retryable = False
        super().__init__(
            "TASK_V2_API_ERROR",
            status_code=status_code,
            retry_after_seconds=retry_after_seconds,
            request_bytes_sent=True,
            retryable=retryable,
        )
        self.public_error_code = public_error_code


class ClaimOutcomeUnknownError(TaskV2Error):
    def __init__(self) -> None:
        super().__init__(
            "CLAIM_OUTCOME_UNKNOWN",
            request_bytes_sent=True,
            retryable=False,
        )


class CompletionOutcomeUnknownError(TaskV2Error):
    def __init__(self) -> None:
        super().__init__(
            "COMPLETION_OUTCOME_UNKNOWN",
            request_bytes_sent=True,
            retryable=False,
        )


@dataclass(frozen=True)
class TaskV2RawResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


Exchange = Callable[
    [str, str, Optional[str], Mapping[str, str], bytes], TaskV2RawResponse
]


def _finite_retry_after(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0:
        return None
    return min(30.0, result)


def _header_value(headers: Mapping[str, str], name: str) -> Optional[str]:
    result: Optional[str] = None
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            if result is not None:
                return None
            result = str(value)
    return result


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                return None
            seconds = parsed.timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            return None
    return _finite_retry_after(max(0.0, seconds))


class TaskV2Transport:
    """Route-closed v2 transport.

    ``exchange`` is an intentionally narrow deterministic seam used by local
    tests.  Production defaults still resolve the fixed API host afresh,
    reject the complete answer set on one unsafe address, and pin one address
    in a no-proxy, no-redirect HTTP/1.1 transport.
    """

    def __init__(
        self,
        *,
        exchange: Optional[Exchange] = None,
        resolver: Callable[[str, int], Sequence[str]] = _resolve_addresses,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        if exchange is not None and not callable(exchange):
            raise ValueError("Invalid v2 exchange.")
        self._resolver = resolver
        self._monotonic = monotonic
        self._sleep = sleep
        self._random_source = random_source
        self._exchange = exchange or self._default_exchange
        self._closed = False

    def __enter__(self) -> "TaskV2Transport":
        if self._closed:
            raise TaskV2TransportError("TASK_V2_TRANSPORT_CLOSED")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def _default_exchange(
        self,
        method: str,
        path: str,
        query: Optional[str],
        headers: Mapping[str, str],
        body: bytes,
    ) -> TaskV2RawResponse:
        tracker = _WriteTracker()
        transport: Optional[httpx.HTTPTransport] = None
        try:
            addresses_raw = self._resolver(PUBLIC_API_HOST, 443)
            addresses = tuple(sorted(set(str(item) for item in addresses_raw)))
            if not addresses or not all(_address_is_public_unicast(item) for item in addresses):
                raise TaskV2TransportError(
                    "TASK_V2_DNS_POLICY_REJECTED", request_bytes_sent=False
                )
            deadline = self._monotonic() + 20.0
            transport = _new_pinned_httpx_transport(
                addresses[0], tracker, deadline, self._monotonic
            )
            url = PUBLIC_API_ORIGIN + path
            if query is not None:
                url += "?" + query
            timeout = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)
            with httpx.Client(
                transport=transport,
                trust_env=False,
                follow_redirects=False,
                cookies=None,
                timeout=timeout,
            ) as client:
                transport = None
                with client.stream(
                    method,
                    url,
                    headers=dict(headers),
                    content=body if body else None,
                ) as response:
                    header_bytes = sum(
                        len(str(key).encode("latin-1", errors="strict"))
                        + len(str(value).encode("latin-1", errors="strict"))
                        + 4
                        for key, value in response.headers.multi_items()
                    )
                    if header_bytes > TASK_V2_MAXIMUM_RESPONSE_HEADER_BYTES:
                        raise TaskV2TransportError(
                            "TASK_V2_RESPONSE_TOO_LARGE",
                            request_bytes_sent=tracker.request_bytes_sent,
                        )
                    content_encoding = response.headers.get("content-encoding")
                    if content_encoding is not None and content_encoding.lower() != "identity":
                        raise TaskV2TransportError(
                            "TASK_V2_RESPONSE_ENCODING_REJECTED",
                            request_bytes_sent=tracker.request_bytes_sent,
                        )
                    chunks = []
                    total = 0
                    for chunk in response.iter_raw():
                        total += len(chunk)
                        if total > TASK_V2_MAXIMUM_JSON_BYTES:
                            raise TaskV2TransportError(
                                "TASK_V2_RESPONSE_TOO_LARGE",
                                request_bytes_sent=tracker.request_bytes_sent,
                            )
                        chunks.append(bytes(chunk))
                    return TaskV2RawResponse(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=b"".join(chunks),
                    )
        except TaskV2Error:
            raise
        except httpx.TimeoutException:
            raise TaskV2TransportError(
                "TASK_V2_TIMEOUT",
                request_bytes_sent=tracker.request_bytes_sent,
                retryable=True,
            ) from None
        except Exception:
            raise TaskV2TransportError(
                "TASK_V2_TRANSPORT_ERROR",
                request_bytes_sent=tracker.request_bytes_sent,
                retryable=True,
            ) from None
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    @staticmethod
    def _headers(
        *, claim_token: Optional[str] = None, submission_id: Optional[str] = None
    ) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": TASK_V2_USER_AGENT,
        }
        if claim_token is not None:
            headers[CLAIM_TOKEN_HEADER] = validate_claim_token(claim_token)
        if submission_id is not None:
            headers[IDEMPOTENCY_KEY_HEADER] = validate_submission_id(submission_id)
        return headers

    def _once(
        self,
        method: str,
        path: str,
        *,
        query: Optional[str] = None,
        claim_token: Optional[str] = None,
        submission_id: Optional[str] = None,
        body: bytes = b"",
        expected_status: Optional[int] = None,
    ) -> Dict[str, Any]:
        if self._closed:
            raise TaskV2TransportError("TASK_V2_TRANSPORT_CLOSED")
        headers = self._headers(
            claim_token=claim_token, submission_id=submission_id
        )
        if body:
            headers["Content-Type"] = "application/json"
        try:
            raw = self._exchange(method, path, query, headers, body)
        except TaskV2Error:
            raise
        except Exception:
            raise TaskV2TransportError(
                "TASK_V2_TRANSPORT_ERROR", request_bytes_sent=None, retryable=True
            ) from None
        if not isinstance(raw, TaskV2RawResponse):
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )
        if type(raw.status_code) is not int or not 100 <= raw.status_code <= 599:
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )
        status_code = raw.status_code
        retry_after = _parse_retry_after(_header_value(raw.headers, "Retry-After"))
        try:
            payload = decode_json_object(raw.body, TASK_V2_MAXIMUM_JSON_BYTES)
        except ValueError:
            raw = None
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            ) from None
        raw = None
        if 200 <= status_code <= 299:
            if expected_status is not None and status_code != expected_status:
                payload.clear()
                raise TaskV2TransportError(
                    "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
                )
            return payload
        self._raise_api(status_code, payload, retry_after)
        raise AssertionError("unreachable")

    @staticmethod
    def _raise_api(
        status_code: int,
        payload: Mapping[str, Any],
        retry_after: Optional[float],
    ) -> None:
        # The one pre-profile exception is the released flat unknown-task body.
        if (
            status_code == 404
            and set(payload.keys()) == {"error_code"}
            and payload.get("error_code") == "not_found"
        ):
            if isinstance(payload, dict):
                payload.clear()
            raise TaskV2APIError("not_found", status_code=404)
        try:
            envelope = ScheduledTaskErrorResponse.model_validate(payload)
        except (TypeError, ValueError, ValidationError):
            if isinstance(payload, dict):
                payload.clear()
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            ) from None
        code = envelope.error.code
        retryable = bool(envelope.error.retryable)
        envelope = None
        if isinstance(payload, dict):
            payload.clear()
        payload = {}
        if code not in V2_ERROR_CODES_BY_STATUS.get(status_code, frozenset()):
            raise TaskV2TransportError(
                "TASK_V2_RESPONSE_INVALID", request_bytes_sent=True
            )
        if code == "claim_outcome_unknown":
            raise ClaimOutcomeUnknownError()
        raise TaskV2APIError(
            code,
            status_code=status_code,
            retry_after_seconds=retry_after,
            retryable=retryable,
        )

    def _public_get(
        self, path: str, *, query: Optional[str] = None
    ) -> Dict[str, Any]:
        last_error: Optional[TaskV2Error] = None
        for attempt in range(3):
            try:
                return self._once(
                    "GET", path, query=query, expected_status=200
                )
            except TaskV2APIError as error:
                last_error = error
                retry = (
                    error.status_code in _RETRYABLE_GET_STATUSES and error.retryable
                )
            except TaskV2TransportError as error:
                last_error = error
                retry = error.retryable
            if not retry or attempt >= 2:
                raise last_error
            delay = last_error.retry_after_seconds
            if delay is None:
                jitter = 0.0
                try:
                    value = float(self._random_source())
                    if math.isfinite(value):
                        jitter = min(1.0, max(0.0, value)) * 0.25
                except Exception:
                    pass
                delay = _PUBLIC_GET_BACKOFF[attempt] + jitter
            self._sleep(delay)
        raise last_error or TaskV2TransportError("TASK_V2_TRANSPORT_ERROR")

    def list_tasks(self) -> Dict[str, Any]:
        return self._public_get(TASK_LIST_PATH, query=TASK_LIST_QUERY)

    def get_task(self, task_id: str) -> Dict[str, Any]:
        return self._public_get(
            task_detail_path(validate_task_id(task_id)), query=TASK_DETAIL_QUERY
        )

    def claim_task(self, task_id: str, body: bytes) -> Dict[str, Any]:
        try:
            return self._once(
                "POST",
                task_claim_path(task_id),
                body=body,
                expected_status=200,
            )
        except ClaimOutcomeUnknownError:
            raise
        except TaskV2TransportError as error:
            if error.request_bytes_sent is not False:
                raise ClaimOutcomeUnknownError() from None
            raise

    def get_readiness(self, task_id: str, claim_token: str) -> Dict[str, Any]:
        return self._once(
            "GET",
            task_readiness_path(task_id),
            claim_token=claim_token,
            expected_status=200,
        )

    def abandon_claim(
        self, task_id: str, claim_token: str, body: bytes
    ) -> Dict[str, Any]:
        return self._once(
            "POST",
            task_abandon_path(task_id),
            claim_token=claim_token,
            body=body,
            expected_status=200,
        )

    def post_completion_bytes(
        self,
        task_id: str,
        claim_token: str,
        submission_id: str,
        body: bytes,
    ) -> Dict[str, Any]:
        try:
            return self._once(
                "POST",
                task_completion_path(task_id),
                claim_token=claim_token,
                submission_id=submission_id,
                body=body,
                expected_status=202,
            )
        except TaskV2TransportError as error:
            if error.request_bytes_sent is not False:
                raise CompletionOutcomeUnknownError() from None
            raise

    def get_submission_status(
        self, task_id: str, submission_id: str
    ) -> Dict[str, Any]:
        return self._public_get(task_status_path(task_id, submission_id))


__all__ = [
    "TaskV2Transport",
    "TaskV2RawResponse",
    "TaskV2Error",
    "TaskV2TransportError",
    "TaskV2APIError",
    "ClaimOutcomeUnknownError",
    "CompletionOutcomeUnknownError",
]
