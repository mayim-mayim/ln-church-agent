"""Route-closed, one-request transport for Paid Service Trials; no lower retry."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import wraps
import time
import re
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
from urllib.parse import urlencode

import httpx

from . import paid_service_trial_contract as c

from .task_transport import _WriteTracker, _new_pinned_httpx_transport, _resolve_addresses
from .network_fetch import _resolve_public_addresses
from .paid_service_trial_contract import (
    PUBLIC_API_ORIGIN, PUBLIC_API_HOST, TASK_LIST_PATH, TASK_TYPE, TASK_SCHEMA_VERSION,
    CLAIM_TOKEN_HEADER, IDEMPOTENCY_KEY_HEADER, ERROR_SCHEMA_VERSION, ERROR_CODES_BY_STATUS,
    decode_json_object, positive_bound, validate_claim_token, validate_opaque_id,
    validate_submission_id, task_detail_path, task_claim_path, task_abandon_path,
    task_completion_path, task_status_path,
)

MAXIMUM_JSON_BYTES = 4 * 1024 * 1024  # bounded 100-Task page with ten 2-KiB endpoints each
MAXIMUM_RESPONSE_HEADER_BYTES = 32768
USER_AGENT = "ln-church-agent-paid-service-trial/1.18.7"
_SAFE_CODES = frozenset({
    "TRANSPORT_CLOSED", "CLIENT_CLOSED", "REQUEST_INVALID", "RESPONSE_INVALID", "TIMEOUT",
    "TRANSPORT_ERROR", "DNS_POLICY_REJECTED", "RESPONSE_TOO_LARGE", "RESPONSE_ENCODING_REJECTED",
    "CREDENTIAL_INVALID", "REPORT_INVALID", "RESPONSE_BINDING_INVALID", "CLAIM_OUTCOME_UNKNOWN",
    "COMPLETION_OUTCOME_UNKNOWN", "API_ERROR",
})


def _safe_request_id(value: Any) -> Optional[str]:
    """Optional presentation only; never reject or rewrite a wire identifier."""
    return value if isinstance(value, str) and re.fullmatch(r'[\x21-\x7e]{1,256}', value) else None


class PaidServiceTrialError(Exception):
    def __init__(self, code: str, *, status_code: Optional[int] = None,
                 request_bytes_sent: Optional[bool] = None,
                 public_error_code: Optional[str] = None, reason: Optional[str] = None,
                 request_id: Optional[str] = None) -> None:
        self.code = code if code in _SAFE_CODES else "TRANSPORT_ERROR"
        self.status_code = status_code if type(status_code) is int and 100 <= status_code <= 599 else None
        self.request_bytes_sent = request_bytes_sent if type(request_bytes_sent) is bool else None
        self.public_error_code = (public_error_code if isinstance(public_error_code, str)
            and public_error_code in ERROR_CODES_BY_STATUS.get(self.status_code, ()) else None)
        self.reason = (reason if self.public_error_code == 'unsupported_purchase_terms'
            and isinstance(reason, str) and reason in c.V2_TERMS_REASONS else None)
        self.request_id = _safe_request_id(request_id)
        super().__init__(self.code)


class PaidServiceTrialTransportError(PaidServiceTrialError):
    pass


class PaidServiceTrialAPIError(PaidServiceTrialError):
    def __init__(self, public_error_code: str, *, status_code: int, reason: Optional[str]=None,
                 request_id: Optional[str]=None) -> None:
        super().__init__("API_ERROR", status_code=status_code, request_bytes_sent=True,
                         public_error_code=public_error_code, reason=reason, request_id=request_id)
        if self.public_error_code is None:
            self.public_error_code = "invalid_response"


def _public_boundary(function: Any) -> Any:
    """Detach the full exception graph, including hidden JSON/body contexts."""
    @wraps(function)
    def call(*args: Any, **kwargs: Any) -> Any:
        detached = None
        try:
            return function(*args, **kwargs)
        except PaidServiceTrialAPIError as error:
            detached = PaidServiceTrialAPIError(error.public_error_code, status_code=error.status_code,
                                               reason=error.reason, request_id=error.request_id)
        except PaidServiceTrialError as error:
            detached = PaidServiceTrialTransportError(error.code, status_code=error.status_code,
                                                    request_bytes_sent=error.request_bytes_sent,
                                                    public_error_code=error.public_error_code,
                                                    reason=error.reason, request_id=error.request_id)
        except ValueError:
            detached = ValueError("Invalid Paid Service Trial request.")
        if detached is not None:
            raise detached
    return call


@dataclass(frozen=True)
class PaidServiceTrialRawResponse:
    status_code: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


class _ResponsePayload(dict):
    """Keep actual received status outside the closed wire/DTO fields."""
    def __init__(self, payload: Dict[str, Any], status: int) -> None:
        super().__init__(payload)
        self._http_status = status


Exchange = Callable[[str, str, Optional[str], Mapping[str, str], bytes, float], PaidServiceTrialRawResponse]


class PaidServiceTrialTransport:
    """Every method performs at most one HTTP request, including authenticated status."""

    def __init__(self, *, version: str='v2', exchange: Optional[Exchange] = None,
                 resolver: Callable[[str, int], Sequence[str]] = _resolve_addresses,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if exchange is not None and not callable(exchange):
            raise ValueError("Invalid Paid Service Trial exchange.")
        self.version = c.validate_version(version)
        self._exchange = exchange or self._default_exchange
        self._resolver = resolver
        self._monotonic = monotonic
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> "PaidServiceTrialTransport":
        if self._closed:
            raise PaidServiceTrialTransportError("TRANSPORT_CLOSED", request_bytes_sent=False)
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _default_exchange(self, method: str, path: str, query: Optional[str],
                          headers: Mapping[str, str], body: bytes,
                          timeout_seconds: float) -> PaidServiceTrialRawResponse:
        tracker = _WriteTracker()
        transport = None
        status = None
        deadline = self._monotonic() + timeout_seconds
        try:
            addresses = _resolve_public_addresses(PUBLIC_API_HOST, resolver=self._resolver,
                                                   timeout=min(5.0, timeout_seconds))
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise PaidServiceTrialTransportError("TIMEOUT", request_bytes_sent=False)
            transport = _new_pinned_httpx_transport(addresses[0], tracker, deadline, self._monotonic)
            url = PUBLIC_API_ORIGIN + path + (("?" + query) if query is not None else "")
            # Read may use the remaining API budget; the pinned stream clamps
            # every read to this same absolute deadline, including body chunks.
            timeout = httpx.Timeout(connect=min(5.0, remaining), read=remaining,
                                    write=min(10.0, remaining), pool=min(5.0, remaining))
            with httpx.Client(transport=transport, trust_env=False, follow_redirects=False,
                              cookies=None, timeout=timeout) as client:
                transport = None
                with client.stream(method, url, headers=dict(headers), content=body or None) as response:
                    status = response.status_code
                    header_bytes = sum(len(k.encode("latin-1")) + len(v.encode("latin-1")) + 4
                                       for k, v in response.headers.multi_items())
                    if header_bytes > MAXIMUM_RESPONSE_HEADER_BYTES:
                        raise PaidServiceTrialTransportError("RESPONSE_TOO_LARGE", request_bytes_sent=tracker.request_bytes_sent)
                    encodings = response.headers.get_list("content-encoding")
                    if encodings and (len(encodings) != 1 or encodings[0].strip().lower() != "identity"):
                        raise PaidServiceTrialTransportError("RESPONSE_ENCODING_REJECTED", request_bytes_sent=tracker.request_bytes_sent)
                    chunks = []
                    total = 0
                    for chunk in response.iter_raw():
                        if self._monotonic() >= deadline:
                            raise PaidServiceTrialTransportError("TIMEOUT", request_bytes_sent=tracker.request_bytes_sent)
                        total += len(chunk)
                        if total > MAXIMUM_JSON_BYTES:
                            raise PaidServiceTrialTransportError("RESPONSE_TOO_LARGE", request_bytes_sent=tracker.request_bytes_sent)
                        chunks.append(bytes(chunk))
                    if self._monotonic() >= deadline:
                        raise PaidServiceTrialTransportError("TIMEOUT", request_bytes_sent=tracker.request_bytes_sent)
                    return PaidServiceTrialRawResponse(response.status_code, dict(response.headers), b"".join(chunks))
        except PaidServiceTrialError as error:
            raise PaidServiceTrialTransportError(error.code, status_code=status,
                request_bytes_sent=error.request_bytes_sent) from None
        except httpx.TimeoutException:
            raise PaidServiceTrialTransportError("TIMEOUT", status_code=status, request_bytes_sent=tracker.request_bytes_sent) from None
        except Exception:
            raise PaidServiceTrialTransportError("TRANSPORT_ERROR", status_code=status, request_bytes_sent=tracker.request_bytes_sent) from None
        finally:
            if transport is not None:
                transport.close()

    @_public_boundary
    def _once(self, method: str, path: str, *, query: Optional[str] = None,
              claim_token: Optional[str] = None, idempotency_key: Optional[str] = None,
              body: bytes = b"", timeout_seconds: float = 20.0,
              expected_statuses: tuple = (200,), version: Optional[str] = None) -> Dict[str, Any]:
        version = self.version if version is None else c.validate_version(version)
        positive_bound(timeout_seconds, "timeout_seconds")
        if self._closed:
            raise PaidServiceTrialTransportError("TRANSPORT_CLOSED", request_bytes_sent=False)
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": USER_AGENT}
        if claim_token is not None:
            headers[CLAIM_TOKEN_HEADER] = validate_claim_token(claim_token)
        if idempotency_key is not None:
            headers[IDEMPOTENCY_KEY_HEADER] = validate_opaque_id(idempotency_key, "idempotency_key")
        if len(body) > 65536:
            raise ValueError("Paid trial request too large.")
        if body:
            headers["Content-Type"] = "application/json"
        try:
            raw = self._exchange(method, path, query, headers, body, float(timeout_seconds))
        except PaidServiceTrialError:
            raise
        except Exception:
            raise PaidServiceTrialTransportError("TRANSPORT_ERROR", request_bytes_sent=None) from None
        if not isinstance(raw, PaidServiceTrialRawResponse) or type(raw.status_code) is not int:
            raise PaidServiceTrialTransportError("RESPONSE_INVALID", request_bytes_sent=True)
        status = raw.status_code
        try:
            if not isinstance(raw.headers, Mapping) or sum(len(str(k)) + len(str(v)) + 4 for k, v in raw.headers.items()) > MAXIMUM_RESPONSE_HEADER_BYTES:
                raise ValueError
            encodings = [v for k, v in raw.headers.items() if str(k).lower() == "content-encoding"]
            if encodings and (len(encodings) != 1 or str(encodings[0]).strip().lower() != "identity"):
                raise ValueError
            payload = decode_json_object(raw.body, MAXIMUM_JSON_BYTES)
        except Exception:
            raise PaidServiceTrialTransportError("RESPONSE_INVALID", status_code=status, request_bytes_sent=True) from None
        if status in expected_statuses:
            return _ResponsePayload(payload, status)
        if 200 <= status <= 299:
            raise PaidServiceTrialTransportError("RESPONSE_INVALID", status_code=status, request_bytes_sent=True)
        fields = {'schema_version', 'code', 'message', 'request_id'} | ({'reason'} if version=='v2' else set())
        reason = payload.get('reason')
        reason_valid = (version=='v1' or
            (reason in c.V2_TERMS_REASONS if payload.get('code')=='unsupported_purchase_terms' and isinstance(reason,str)
             else reason is None and payload.get('code')!='unsupported_purchase_terms'))
        if (set(payload) == fields
                and payload.get('schema_version') == 'ln_church.task_error.paid_service_trial.'+version
                and isinstance(payload.get('code'), str)
                and payload.get('code') in ERROR_CODES_BY_STATUS.get(status, ())
                and isinstance(payload.get('message'), str) and isinstance(payload.get('request_id'), str)
                and reason_valid):
            code = payload['code']; request_id = _safe_request_id(payload['request_id']); payload.clear()
            raise PaidServiceTrialAPIError(code, status_code=status, reason=reason, request_id=request_id)
        payload.clear()
        raise PaidServiceTrialTransportError("RESPONSE_INVALID", status_code=status, request_bytes_sent=True)

    def list_tasks(self, *, limit: int = 25, cursor: Optional[str] = None, timeout_seconds: float = 20.0) -> Dict[str, Any]:
        positive_bound(limit, "limit", integer=True, maximum=50)
        query = {"task_type": "paid_service_trial."+self.version, "task_schema_version": "ln_church.agent_task.paid_service_trial."+self.version, "limit": str(limit)}
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor or len(cursor.encode("utf-8")) > 1024:
                raise ValueError("Invalid cursor.")
            from .paid_service_trial_contract import cursor as validate_cursor
            query["cursor"] = validate_cursor(cursor)
        return self._once("GET", TASK_LIST_PATH, query=urlencode(query), timeout_seconds=timeout_seconds)

    def get_task(self, task_id: str, *, timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("GET", task_detail_path(task_id), query=urlencode({"task_schema_version": "ln_church.agent_task.paid_service_trial."+self.version}), timeout_seconds=timeout_seconds)

    def claim_task(self, task_id: str, body: bytes, *, idempotency_key: str,
                   timeout_seconds: float = 20.0) -> Dict[str, Any]:
        return self._once("POST", task_claim_path(task_id), body=body, idempotency_key=idempotency_key,
                          timeout_seconds=timeout_seconds)

    def abandon_claim(self, task_id: str, claim_token: str, body: bytes, *, idempotency_key: str,
                      timeout_seconds: float = 20.0, version: Optional[str] = None) -> Dict[str, Any]:
        return self._once("POST", task_abandon_path(task_id), claim_token=claim_token,
                          idempotency_key=idempotency_key, body=body, timeout_seconds=timeout_seconds, version=version)

    def post_completion_bytes(self, task_id: str, claim_token: str, submission_id: str, body: bytes,
                              *, idempotency_key: Optional[str] = None, timeout_seconds: float = 20.0, version: Optional[str] = None) -> Dict[str, Any]:
        return self._once("POST", task_completion_path(task_id), claim_token=claim_token,
                          idempotency_key=idempotency_key or validate_submission_id(submission_id), body=body,
                          timeout_seconds=timeout_seconds, expected_statuses=(200, 202), version=version)

    def get_submission_status(self, task_id: str, submission_id: str, claim_token: str,
                              *, timeout_seconds: float = 20.0, version: Optional[str] = None) -> Dict[str, Any]:
        return self._once("GET", task_status_path(task_id, submission_id), claim_token=claim_token,
                          timeout_seconds=timeout_seconds, version=version)
