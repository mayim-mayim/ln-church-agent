"""Dedicated no-payment transport for the public Agent Task API.

The Task lane is intentionally isolated from :class:`LnChurchClient` and its
payment/navigation machinery.  This module accepts only the fixed public
origin and fixed Task routes, validates every DNS answer, pins one vetted
address for each request, and keeps the original hostname for HTTP Host, TLS
SNI, and certificate verification.

Only finite, secret-free errors leave this module.  In particular, remote
response bodies, headers, cookies, request URLs, and underlying exceptions are
never retained by a public exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import wraps
import ipaddress
import json
import math
import queue
import random
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlencode

import httpcore
import httpx

from .redaction import _inspect_address_is_forbidden
from .task_contract import (
    CLAIM_TOKEN_HEADER,
    LOCAL_AMBIGUOUS_DELIVERY_CODES,
    LOCAL_ERROR_CODES,
    MAXIMUM_JSON_BYTES,
    MUTATION_FREE_CLAIM_ERROR_CODES_BY_STATUS,
    PUBLIC_API_ORIGIN,
    PUBLIC_ERROR_CODES_BY_STATUS,
    RETRYABLE_HTTP_STATUSES,
    TASK_STATUSES,
    TASK_TYPE_PAYMENT_SURFACE_DISCOVERY,
    validate_claim_token,
)


TASK_API_ORIGIN = PUBLIC_API_ORIGIN
TASK_API_HOST = "kari.mayim-mayim.com"
TASK_API_PORT = 443
TASK_CLAIM_HEADER = CLAIM_TOKEN_HEADER
TASK_MAX_JSON_BYTES = MAXIMUM_JSON_BYTES

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_TASK_PATH_SEGMENT_PATTERN = (
    r"([A-Za-z0-9._~-]{1,128}|%2E(?:%2E)?)"
)
_SUBMISSION_ID_PATH_SEGMENT_PATTERN = r"(sub_[a-f0-9]{32})"
_GET_TASK_RE = re.compile(
    r"^/api/agent/tasks/" + _TASK_PATH_SEGMENT_PATTERN + r"$"
)
_GET_SUBMISSION_STATUS_RE = re.compile(
    r"^/api/agent/tasks/"
    + _TASK_PATH_SEGMENT_PATTERN
    + r"/submissions/"
    + _SUBMISSION_ID_PATH_SEGMENT_PATTERN
    + r"/status$"
)
_POST_TASK_RE = re.compile(
    r"^/api/agent/tasks/" + _TASK_PATH_SEGMENT_PATTERN + r"/"
    r"(claim|domain-observations|completion)$"
)
_LOCAL_CODES = frozenset(LOCAL_ERROR_CODES)
_AMBIGUOUS_CODES = frozenset(LOCAL_AMBIGUOUS_DELIVERY_CODES)
_RETRYABLE_STATUSES = frozenset(RETRYABLE_HTTP_STATUSES)
_EXPECTED_SUCCESS_STATUSES = frozenset({200})
_MAX_RETRY_AFTER_SECONDS = 30.0
_TASK_SPECIAL_V4_192 = ipaddress.ip_network("192.0.0.0/24")
_TASK_SPECIAL_V4_192_GLOBAL = frozenset(
    {
        ipaddress.ip_address("192.0.0.9"),
        ipaddress.ip_address("192.0.0.10"),
    }
)
_TASK_DEPRECATED_6TO4_RELAY = ipaddress.ip_network("192.88.99.0/24")
_TASK_SPECIAL_V6_2001 = ipaddress.ip_network("2001::/23")
_TASK_SPECIAL_V6_2001_GLOBAL = (
    ipaddress.ip_network("2001:1::1/128"),
    ipaddress.ip_network("2001:1::2/128"),
    ipaddress.ip_network("2001:3::/32"),
    ipaddress.ip_network("2001:4:112::/48"),
    ipaddress.ip_network("2001:20::/28"),
    ipaddress.ip_network("2001:30::/28"),
)
_TASK_DOCUMENTATION_V6 = ipaddress.ip_network("3fff::/20")


class TaskError(Exception):
    """Base public Task error with finite, secret-free metadata."""

    def __init__(
        self,
        code: str,
        *,
        status_code: Optional[int] = None,
        request_bytes_sent: Optional[bool] = None,
        mutation_free: bool = False,
        retry_after_seconds: Optional[float] = None,
        _retryable_transport: bool = False,
    ) -> None:
        if code not in _LOCAL_CODES and code not in _AMBIGUOUS_CODES:
            code = "TASK_TRANSPORT_ERROR"
        if (
            type(status_code) is not int
            or status_code < 100
            or status_code > 599
        ):
            status_code = None
        if request_bytes_sent not in (True, False, None):
            request_bytes_sent = None
        if type(mutation_free) is not bool:
            mutation_free = False
        retry_after_seconds = _sanitize_retry_after_number(
            retry_after_seconds
        )

        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.request_bytes_sent = request_bytes_sent
        self.mutation_free = mutation_free
        self.retry_after_seconds = retry_after_seconds
        self._retryable_transport = bool(_retryable_transport)

    @property
    def request_bytes_maybe_sent(self) -> bool:
        """Compatibility view: only an explicit ``False`` proves no send."""

        return self.request_bytes_sent is not False


class TaskTransportError(TaskError):
    """A local transport, policy, or response-boundary failure."""


class TaskAPIError(TaskError):
    """A complete finite error returned by the public Task API."""

    def __init__(
        self,
        code: str = "TASK_API_ERROR",
        *,
        public_error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        request_bytes_sent: Optional[bool] = True,
        mutation_free: bool = False,
        retry_after_seconds: Optional[float] = None,
    ) -> None:
        # Retain the ordinary TaskError call shape without allowing a caller
        # to turn remote text into the exception message.
        if code != "TASK_API_ERROR":
            code = "TASK_API_ERROR"
        allowed = PUBLIC_ERROR_CODES_BY_STATUS.get(status_code, frozenset())
        if public_error_code not in allowed:
            public_error_code = None
            mutation_free = False
        super().__init__(
            "TASK_API_ERROR",
            status_code=status_code,
            request_bytes_sent=request_bytes_sent,
            mutation_free=mutation_free,
            retry_after_seconds=retry_after_seconds,
        )
        self.public_error_code = public_error_code


class TaskAmbiguousOutcomeError(TaskTransportError):
    """A mutation may have committed and must not be blindly replayed."""

    def __init__(
        self,
        code: str,
        *,
        status_code: Optional[int] = None,
        request_bytes_sent: Optional[bool] = None,
        retry_after_seconds: Optional[float] = None,
    ) -> None:
        if code not in _AMBIGUOUS_CODES:
            code = "SUBMISSION_OUTCOME_UNKNOWN"
        super().__init__(
            code,
            status_code=status_code,
            request_bytes_sent=request_bytes_sent,
            mutation_free=False,
            retry_after_seconds=retry_after_seconds,
        )


def _detached_task_error(error: TaskError) -> TaskError:
    """Copy only finite public metadata, dropping traceback and exception graph."""

    if isinstance(error, TaskAPIError):
        return TaskAPIError(
            public_error_code=error.public_error_code,
            status_code=error.status_code,
            request_bytes_sent=error.request_bytes_sent,
            mutation_free=error.mutation_free,
            retry_after_seconds=error.retry_after_seconds,
        )
    if isinstance(error, TaskAmbiguousOutcomeError):
        return TaskAmbiguousOutcomeError(
            error.code,
            status_code=error.status_code,
            request_bytes_sent=error.request_bytes_sent,
            retry_after_seconds=error.retry_after_seconds,
        )
    if isinstance(error, TaskTransportError):
        return TaskTransportError(
            error.code,
            status_code=error.status_code,
            request_bytes_sent=error.request_bytes_sent,
            mutation_free=error.mutation_free,
            retry_after_seconds=error.retry_after_seconds,
            _retryable_transport=error._retryable_transport,
        )
    return TaskError(
        error.code,
        status_code=error.status_code,
        request_bytes_sent=error.request_bytes_sent,
        mutation_free=error.mutation_free,
        retry_after_seconds=error.retry_after_seconds,
        _retryable_transport=error._retryable_transport,
    )


def _public_task_error_boundary(function: Callable[..., Any]) -> Callable[..., Any]:
    """Ensure an exported transport call never retains an internal exception."""

    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        clean_error: Optional[TaskError] = None
        try:
            return function(*args, **kwargs)
        except TaskError as error:
            clean_error = _detached_task_error(error)
        except Exception:
            clean_error = TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=None
            )
        args = ()
        kwargs.clear()
        raise clean_error

    return wrapped


def _claim_secret_key(value: Any) -> bool:
    if type(value) is not str:
        return False
    compact = value.lower().replace("-", "").replace("_", "")
    return compact in {
        "claimtoken",
        "taskclaimtoken",
        "xlntaskclaimtoken",
    }


def _collect_claim_secret_values(value: Any) -> Tuple[str, ...]:
    collected: List[str] = []

    def collect(candidate: Any) -> None:
        if type(candidate) is dict:
            for key, item in candidate.items():
                if _claim_secret_key(key) and type(item) is str and item:
                    collected.append(item)
                collect(item)
        elif type(candidate) is list:
            for item in candidate:
                collect(item)

    collect(value)
    return tuple(collected)


def _sanitize_response_value(
    value: Any,
    known_claim_tokens: Sequence[str],
) -> Any:
    if type(value) is dict:
        return {
            key: _sanitize_response_value(item, known_claim_tokens)
            for key, item in value.items()
            if not _claim_secret_key(key)
        }
    if type(value) is list:
        return [
            _sanitize_response_value(item, known_claim_tokens)
            for item in value
        ]
    if (
        type(value) is str
        and any(token in value for token in known_claim_tokens)
    ):
        return "[REDACTED]"
    return value


class TaskTransportResponse:
    """Bounded response payload.

    A successful Claim's bearer is held outside the normally visible mapping
    and is exposed only through the package-private conversion accessor.
    """

    __slots__ = ("status_code", "_data", "_claim_token")

    def __init__(self, status_code: int, data: Mapping[str, Any]) -> None:
        if type(status_code) is not int or not 100 <= status_code <= 599:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            )
        if type(data) is not dict:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            )
        copied = dict(data)
        known_claim_tokens = _collect_claim_secret_values(copied)
        claim_token = copied.pop("claim_token", None)
        sanitized = _sanitize_response_value(
            copied,
            known_claim_tokens,
        )
        if type(sanitized) is not dict:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID", request_bytes_sent=True
            )
        self.status_code = status_code
        self._data = sanitized
        self._claim_token = claim_token

    @property
    def data(self) -> Dict[str, Any]:
        """Return a copy of the non-secret response mapping."""

        return dict(self._data)

    def _claim_data_for_model(self) -> Dict[str, Any]:
        payload = dict(self._data)
        if self._claim_token is not None:
            payload["claim_token"] = self._claim_token
        return payload

    def __repr__(self) -> str:
        return "TaskTransportResponse(status_code=%d, data=<bounded>)" % (
            self.status_code,
        )


@dataclass
class _WriteTracker:
    # None is deliberately distinct from False.  A test seam or an
    # uninstrumented exchange cannot prove that zero HTTP request bytes left.
    request_bytes_sent: Optional[bool] = False

    @property
    def request_bytes_maybe_sent(self) -> bool:
        return self.request_bytes_sent is not False

    @request_bytes_maybe_sent.setter
    def request_bytes_maybe_sent(self, value: bool) -> None:
        # Compatibility with the pre-R01 private test seam.
        self.request_bytes_sent = True if value else False


class _TaskExchangeBudget:
    """Shared bound for the HTTP exchanges in one higher-level operation."""

    __slots__ = ("remaining",)

    def __init__(self, maximum_exchanges: int) -> None:
        if (
            type(maximum_exchanges) is not int
            or not 1 <= maximum_exchanges <= 10
        ):
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            )
        self.remaining = maximum_exchanges

    def consume(self) -> None:
        if self.remaining <= 0:
            raise TaskTransportError(
                "TASK_TIMEOUT", request_bytes_sent=False
            )
        self.remaining -= 1


def _sanitize_retry_after_number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    converted = float(value)
    if not math.isfinite(converted) or converted < 0.0:
        return None
    return min(_MAX_RETRY_AFTER_SECONDS, converted)


def _merge_request_byte_states(
    first: Optional[bool], second: Optional[bool]
) -> Optional[bool]:
    if first is True or second is True:
        return True
    if first is None or second is None:
        return None
    return False


def _remaining(
    deadline: float, monotonic: Callable[[], float]
) -> float:
    try:
        value = float(deadline) - float(monotonic())
    except Exception:
        raise TaskTransportError("TASK_TRANSPORT_ERROR") from None
    if not math.isfinite(value) or value <= 0.0:
        raise TaskTransportError(
            "TASK_TIMEOUT", _retryable_transport=True
        )
    return value


class _TrackingNetworkStream:
    """Delegate an httpcore stream and track writes before delegation."""

    def __init__(
        self,
        stream: Any,
        tracker: _WriteTracker,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> None:
        self._stream = stream
        self._tracker = tracker
        self._deadline = deadline
        self._monotonic = monotonic

    def _timeout(self, requested: Optional[float]) -> float:
        remaining = _remaining(self._deadline, self._monotonic)
        if requested is None:
            return remaining
        try:
            requested_value = float(requested)
        except (TypeError, ValueError):
            return remaining
        if not math.isfinite(requested_value) or requested_value <= 0.0:
            return remaining
        return min(requested_value, remaining)

    def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        return self._stream.read(max_bytes, self._timeout(timeout))

    def write(self, buffer: bytes, timeout: Optional[float] = None) -> None:
        if buffer:
            # Mark first.  A failed write cannot prove that the peer received
            # no part of the HTTP request.
            self._tracker.request_bytes_sent = True
        self._stream.write(buffer, self._timeout(timeout))

    def close(self) -> None:
        self._stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: Any,
        timeout: Optional[float] = None,
    ) -> "_TrackingNetworkStream":
        if isinstance(server_hostname, bytes):
            try:
                hostname = server_hostname.decode("ascii", errors="strict")
            except UnicodeError:
                raise ssl.SSLError("Task TLS hostname rejected") from None
        else:
            hostname = str(server_hostname)
        if hostname != TASK_API_HOST:
            raise ssl.SSLError("Task TLS hostname rejected")
        if (
            not isinstance(ssl_context, ssl.SSLContext)
            or not ssl_context.check_hostname
            or ssl_context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ssl.SSLError("Task TLS verification rejected")
        wrapped = self._stream.start_tls(
            ssl_context=ssl_context,
            server_hostname=server_hostname,
            timeout=self._timeout(timeout),
        )
        return _TrackingNetworkStream(
            wrapped,
            self._tracker,
            self._deadline,
            self._monotonic,
        )

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _PinnedNetworkBackend:
    """Connect to one vetted IP while httpcore retains the URL hostname."""

    def __init__(
        self,
        address: str,
        tracker: _WriteTracker,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> None:
        self._address = address
        self._tracker = tracker
        self._deadline = deadline
        self._monotonic = monotonic
        self._backend = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: Any,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Sequence[Tuple[int, int, int]]] = None,
    ) -> _TrackingNetworkStream:
        if isinstance(host, bytes):
            expected_host = TASK_API_HOST.encode("ascii")
            pinned_host: Any = self._address.encode("ascii")
        else:
            expected_host = TASK_API_HOST
            pinned_host = self._address
        if host != expected_host or port != TASK_API_PORT:
            raise OSError("Task destination rejected")
        if local_address is not None:
            raise OSError("Task local address override rejected")
        remaining = _remaining(self._deadline, self._monotonic)
        if timeout is not None:
            try:
                timeout_value = float(timeout)
            except (TypeError, ValueError):
                timeout_value = remaining
            if math.isfinite(timeout_value) and timeout_value > 0.0:
                remaining = min(remaining, timeout_value)
        stream = self._backend.connect_tcp(
            host=pinned_host,
            port=port,
            timeout=remaining,
            local_address=None,
            socket_options=socket_options,
        )
        return _TrackingNetworkStream(
            stream,
            self._tracker,
            self._deadline,
            self._monotonic,
        )

    def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Sequence[Tuple[int, int, int]]] = None,
    ) -> Any:
        raise OSError("Unix sockets are unavailable")

    def sleep(self, seconds: float) -> None:
        remaining = _remaining(self._deadline, self._monotonic)
        self._backend.sleep(min(max(0.0, float(seconds)), remaining))


def _new_pinned_httpx_transport(
    address: str,
    tracker: _WriteTracker,
    deadline: float,
    monotonic: Callable[[], float],
) -> httpx.HTTPTransport:
    transport = httpx.HTTPTransport(
        verify=True,
        trust_env=False,
        http1=True,
        http2=False,
        retries=0,
    )
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        transport.close()
        raise TaskTransportError(
            "TASK_TRANSPORT_ERROR", request_bytes_sent=False
        )
    pool._network_backend = _PinnedNetworkBackend(
        address, tracker, deadline, monotonic
    )
    # From this point every HTTP write is instrumented.
    tracker.request_bytes_sent = False
    return transport


def _resolve_addresses(host: str, port: int) -> Tuple[str, ...]:
    try:
        records = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError:
        raise TaskTransportError(
            "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
        ) from None
    addresses = tuple(sorted({str(record[4][0]) for record in records}))
    if not addresses:
        raise TaskTransportError(
            "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
        )
    return addresses


def _address_is_public_unicast(address: Any) -> bool:
    # Avoid parser/platform ambiguity around scoped and mapped IPv6 values.
    if "%" in str(address):
        return False
    if isinstance(address, ipaddress.IPv4Address):
        if address in _TASK_DEPRECATED_6TO4_RELAY:
            return False
        if (
            address in _TASK_SPECIAL_V4_192
            and address not in _TASK_SPECIAL_V4_192_GLOBAL
        ):
            return False
    if isinstance(address, ipaddress.IPv6Address):
        if address in _TASK_DOCUMENTATION_V6:
            return False
        if (
            address in _TASK_SPECIAL_V6_2001
            and not any(
                address in network
                for network in _TASK_SPECIAL_V6_2001_GLOBAL
            )
        ):
            return False
    return not _inspect_address_is_forbidden(address)


def _resolve_addresses_bounded(
    resolver: Callable[[str, int], Sequence[str]],
    timeout: float,
) -> Tuple[str, ...]:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or float(timeout) <= 0.0
    ):
        raise TaskTransportError(
            "TASK_TIMEOUT", request_bytes_sent=False
        )

    result_queue: "queue.Queue[Tuple[bool, Any]]" = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            value = resolver(TASK_API_HOST, TASK_API_PORT)
            result_queue.put((True, value))
        except BaseException as exc:
            result_queue.put((False, exc))

    worker = threading.Thread(
        target=resolve,
        name="ln-church-task-dns",
        daemon=True,
    )
    worker.start()
    worker.join(float(timeout))
    if worker.is_alive():
        raise TaskTransportError(
            "TASK_TIMEOUT",
            request_bytes_sent=False,
            _retryable_transport=True,
        )
    try:
        succeeded, value = result_queue.get_nowait()
    except queue.Empty:
        raise TaskTransportError(
            "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
        ) from None
    if not succeeded:
        if isinstance(value, TaskError):
            value.request_bytes_sent = False
            raise value
        raise TaskTransportError(
            "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
        ) from None
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TaskTransportError(
            "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
        )

    validated = []
    for raw in value:
        if not isinstance(raw, str):
            raise TaskTransportError(
                "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
            )
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            raise TaskTransportError(
                "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
            ) from None
        if not _address_is_public_unicast(address):
            raise TaskTransportError(
                "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
            )
        validated.append(address.compressed.lower())
    unique = tuple(sorted(set(validated)))
    if not unique:
        raise TaskTransportError(
            "TASK_DNS_POLICY_REJECTED", request_bytes_sent=False
        )
    return unique


def _classify_method_path(method: Any, path: Any) -> str:
    if type(method) is not str or type(path) is not str:
        raise TaskTransportError(
            "TASK_ORIGIN_INVALID", request_bytes_sent=False
        )
    if method == "GET" and path == "/api/agent/tasks":
        return "list"
    if method == "GET":
        status_match = _GET_SUBMISSION_STATUS_RE.fullmatch(path)
        if status_match:
            if any(
                segment in {".", ".."}
                for segment in status_match.groups()
            ):
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
            return "status"
        detail_match = _GET_TASK_RE.fullmatch(path)
        if detail_match:
            if detail_match.group(1) in {".", ".."}:
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
            return "detail"
    match = _POST_TASK_RE.fullmatch(path) if method == "POST" else None
    if match:
        if match.group(1) in {".", ".."}:
            raise TaskTransportError(
                "TASK_ORIGIN_INVALID", request_bytes_sent=False
            )
        return {
            "claim": "claim",
            "domain-observations": "observation",
            "completion": "completion",
        }[match.group(2)]
    raise TaskTransportError(
        "TASK_ORIGIN_INVALID", request_bytes_sent=False
    )


def _validate_query(
    operation: str, params: Optional[Mapping[str, Any]]
) -> Dict[str, Any]:
    if params is None:
        return {}
    if type(params) is not dict:
        raise TaskTransportError(
            "TASK_ORIGIN_INVALID", request_bytes_sent=False
        )
    if not params:
        return {}
    if operation == "list":
        allowed_keys = {"task_type", "status", "limit", "cursor"}
    elif operation == "detail":
        allowed_keys = {"limit", "cursor"}
    else:
        raise TaskTransportError(
            "TASK_ORIGIN_INVALID", request_bytes_sent=False
        )
    if set(params) - allowed_keys:
        raise TaskTransportError(
            "TASK_ORIGIN_INVALID", request_bytes_sent=False
        )

    normalized: Dict[str, Any] = {}
    for key, value in params.items():
        if key == "task_type":
            if (
                operation != "list"
                or type(value) is not str
                or value != TASK_TYPE_PAYMENT_SURFACE_DISCOVERY
            ):
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
        elif key == "status":
            if (
                operation != "list"
                or type(value) is not str
                or value not in TASK_STATUSES
            ):
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
        elif key == "limit":
            if type(value) is not int or not 1 <= value <= 50:
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
        elif key == "cursor":
            try:
                cursor_size = (
                    len(value.encode("utf-8", errors="strict"))
                    if type(value) is str
                    else -1
                )
            except UnicodeError:
                cursor_size = -1
            if type(value) is not str or not value or not 1 <= cursor_size <= 2048:
                raise TaskTransportError(
                    "TASK_ORIGIN_INVALID", request_bytes_sent=False
                )
        normalized[key] = value
    try:
        urlencode(tuple(normalized.items()))
    except (TypeError, ValueError, UnicodeError):
        raise TaskTransportError(
            "TASK_ORIGIN_INVALID", request_bytes_sent=False
        ) from None
    return normalized


def _encode_body(
    operation: str, body: Optional[Mapping[str, Any]]
) -> Optional[bytes]:
    if operation in {"list", "detail", "status"}:
        if body is not None:
            raise TaskTransportError(
                "TASK_ORIGIN_INVALID", request_bytes_sent=False
            )
        return None
    if type(body) is not dict:
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=False
        )
    try:
        encoded = json.dumps(
            body,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError):
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=False
        ) from None
    if len(encoded) > TASK_MAX_JSON_BYTES:
        raise TaskTransportError(
            "TASK_RESPONSE_TOO_LARGE", request_bytes_sent=False
        )
    return encoded


def _normalize_header_subset(
    headers: Mapping[str, Any],
) -> Dict[str, str]:
    if not isinstance(headers, Mapping):
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=True
        )
    selected: Dict[str, str] = {}
    counts: Dict[str, int] = {}
    try:
        items = headers.items()
        for raw_name, raw_value in items:
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise ValueError
            name = raw_name.strip().lower()
            if name not in {
                "content-encoding",
                "content-length",
                "retry-after",
            }:
                continue
            counts[name] = counts.get(name, 0) + 1
            if counts[name] > 1:
                raise ValueError
            selected[name] = raw_value.strip()
    except Exception:
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID", request_bytes_sent=True
        ) from None
    return selected


def _validate_declared_response(
    status_code: int,
    headers: Mapping[str, str],
    content: bytes,
) -> None:
    content_encoding = headers.get("content-encoding", "").lower()
    if content_encoding not in {"", "identity"}:
        raise TaskTransportError(
            "TASK_RESPONSE_ENCODING_REJECTED",
            status_code=status_code,
            request_bytes_sent=True,
        )
    declared = headers.get("content-length", "")
    if declared:
        try:
            declared_size = int(declared, 10)
        except (TypeError, ValueError):
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID",
                status_code=status_code,
                request_bytes_sent=True,
            ) from None
        if declared_size < 0:
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID",
                status_code=status_code,
                request_bytes_sent=True,
            )
        if declared_size > TASK_MAX_JSON_BYTES:
            raise TaskTransportError(
                "TASK_RESPONSE_TOO_LARGE",
                status_code=status_code,
                request_bytes_sent=True,
            )
        if declared_size != len(content):
            raise TaskTransportError(
                "TASK_RESPONSE_INVALID",
                status_code=status_code,
                request_bytes_sent=True,
            )
    if len(content) > TASK_MAX_JSON_BYTES:
        raise TaskTransportError(
            "TASK_RESPONSE_TOO_LARGE",
            status_code=status_code,
            request_bytes_sent=True,
        )


def _reject_duplicate_object_keys(
    pairs: Sequence[Tuple[str, Any]]
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_non_json_constant(_value: str) -> None:
    raise ValueError("Non-JSON numeric constant")


def _decode_json_object(
    status_code: int,
    headers: Mapping[str, str],
    content: bytes,
) -> Dict[str, Any]:
    _validate_declared_response(status_code, headers, content)
    try:
        text = content.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID",
            status_code=status_code,
            request_bytes_sent=True,
        ) from None
    if type(parsed) is not dict:
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID",
            status_code=status_code,
            request_bytes_sent=True,
        )
    return parsed


def _parse_retry_after(
    raw_value: Optional[str],
    wall_time: Callable[[], float] = time.time,
) -> Optional[float]:
    if not raw_value or not isinstance(raw_value, str):
        return None
    if len(raw_value) > 128 or any(ord(char) < 32 for char in raw_value):
        return None
    try:
        numeric = float(raw_value)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw_value)
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                return None
            now = datetime.fromtimestamp(float(wall_time()), tz=timezone.utc)
            numeric = max(0.0, (parsed.astimezone(timezone.utc) - now).total_seconds())
        except Exception:
            return None
    return _sanitize_retry_after_number(numeric)


def _validate_api_error(
    operation: str,
    status_code: int,
    data: Dict[str, Any],
    retry_after_seconds: Optional[float],
) -> TaskAPIError:
    schema_version = data.get("schema_version")
    public_code = data.get("error_code")
    allowed = PUBLIC_ERROR_CODES_BY_STATUS.get(status_code, frozenset())
    if (
        schema_version != "ln_church.agent_task_error.v1"
        or type(public_code) is not str
        or public_code not in allowed
    ):
        raise TaskTransportError(
            "TASK_RESPONSE_INVALID",
            status_code=status_code,
            request_bytes_sent=True,
        )
    mutation_free = (
        operation == "claim"
        and public_code
        in MUTATION_FREE_CLAIM_ERROR_CODES_BY_STATUS.get(
            status_code, frozenset()
        )
    )
    return TaskAPIError(
        public_error_code=public_code,
        status_code=status_code,
        request_bytes_sent=True,
        mutation_free=mutation_free,
        retry_after_seconds=retry_after_seconds,
    )


def _contains_tls_error(error: BaseException) -> bool:
    seen = set()
    current: Optional[BaseException] = error
    for _ in range(8):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return True
        name = type(current).__name__.lower()
        if "ssl" in name or "certificate" in name:
            return True
        current = current.__cause__ or current.__context__
    return False


def _map_exchange_exception(
    error: BaseException, tracker: _WriteTracker
) -> TaskTransportError:
    state = tracker.request_bytes_sent
    if _contains_tls_error(error):
        return TaskTransportError(
            "TASK_TLS_ERROR", request_bytes_sent=state
        )
    if isinstance(
        error,
        (
            TimeoutError,
            socket.timeout,
            httpx.TimeoutException,
            httpcore.TimeoutException,
        ),
    ):
        return TaskTransportError(
            "TASK_TIMEOUT",
            request_bytes_sent=state,
            _retryable_transport=True,
        )
    if isinstance(
        error,
        (
            OSError,
            httpx.NetworkError,
            httpx.RequestError,
            httpcore.NetworkError,
        ),
    ):
        return TaskTransportError(
            "TASK_TRANSPORT_ERROR",
            request_bytes_sent=state,
            _retryable_transport=True,
        )
    return TaskTransportError(
        "TASK_TRANSPORT_ERROR", request_bytes_sent=state
    )


def _error_is_retryable(operation: str, error: TaskError) -> bool:
    if operation == "claim":
        return False
    if operation not in {
        "list",
        "detail",
        "status",
        "observation",
        "completion",
    }:
        return False
    if error.status_code in _RETRYABLE_STATUSES:
        return True
    return bool(error._retryable_transport) and error.code in {
        "TASK_TIMEOUT",
        "TASK_TRANSPORT_ERROR",
    }


def _ambiguity_required(
    operation: str, error: TaskError
) -> bool:
    if error.request_bytes_sent is False or error.mutation_free:
        return False
    if operation == "claim":
        return True
    if operation in {"observation", "completion"}:
        # A complete finite 4xx (other than 429) is an explicit API outcome.
        # Exhausted transient/5xx results and malformed successes remain
        # ambiguous after the idempotent retry budget is spent.
        if (
            isinstance(error, TaskAPIError)
            and error.public_error_code is not None
            and error.status_code is not None
            and 400 <= error.status_code < 500
            and error.status_code != 429
        ):
            return False
        return True
    return False


class TaskTransport:
    """Fixed-origin synchronous transport for the public Agent Task API."""

    def __init__(
        self,
        api_origin: str = TASK_API_ORIGIN,
        *,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 10.0,
        write_timeout_seconds: float = 10.0,
        pool_timeout_seconds: float = 5.0,
        total_operation_timeout_seconds: float = 20.0,
        _resolver: Optional[
            Callable[[str, int], Sequence[str]]
        ] = None,
        _exchange: Optional[
            Callable[..., Tuple[int, Mapping[str, str], bytes]]
        ] = None,
        _sleep: Callable[[float], None] = time.sleep,
        _monotonic: Callable[[], float] = time.monotonic,
        _random: Callable[[], float] = random.random,
    ) -> None:
        if type(api_origin) is not str or api_origin != TASK_API_ORIGIN:
            raise TaskTransportError(
                "TASK_ORIGIN_INVALID", request_bytes_sent=False
            )
        values = (
            connect_timeout_seconds,
            read_timeout_seconds,
            write_timeout_seconds,
            pool_timeout_seconds,
            total_operation_timeout_seconds,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0.0
            for value in values
        ):
            raise TaskTransportError(
                "TASK_ORIGIN_INVALID", request_bytes_sent=False
            )
        self.api_origin = TASK_API_ORIGIN
        self.connect_timeout_seconds = float(connect_timeout_seconds)
        self.read_timeout_seconds = float(read_timeout_seconds)
        self.write_timeout_seconds = float(write_timeout_seconds)
        self.pool_timeout_seconds = float(pool_timeout_seconds)
        self.total_operation_timeout_seconds = float(
            total_operation_timeout_seconds
        )
        self._resolver = _resolver or _resolve_addresses
        self._exchange = _exchange
        self._sleep = _sleep
        self._monotonic = _monotonic
        self._random = _random
        self._closed = False

    def __enter__(self) -> "TaskTransport":
        if self._closed:
            raise TaskTransportError("TASK_TRANSPORT_ERROR")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def _exchange_once(
        self,
        *,
        method: str,
        path: str,
        params: Mapping[str, Any],
        body: Optional[bytes],
        claim_token: Optional[str],
        address: str,
        deadline: float,
        tracker: _WriteTracker,
    ) -> Tuple[int, Dict[str, str], bytes]:
        remaining = _remaining(deadline, self._monotonic)
        if self._exchange is not None:
            # A package-private injected exchange has no write instrumentation
            # unless it explicitly updates the tracker.
            tracker.request_bytes_sent = None
            result = self._exchange(
                method=method,
                url=TASK_API_ORIGIN + path,
                params=dict(params),
                body=body,
                claim_token=claim_token,
                address=address,
                timeout=remaining,
                tracker=tracker,
            )
            if (
                not isinstance(result, tuple)
                or len(result) != 3
                or type(result[0]) is not int
                or not 100 <= result[0] <= 599
                or not isinstance(result[2], bytes)
            ):
                raise TaskTransportError(
                    "TASK_RESPONSE_INVALID",
                    request_bytes_sent=tracker.request_bytes_sent,
                )
            status_code = result[0]
            headers = _normalize_header_subset(result[1])
            content = result[2]
            # Receiving an HTTP response proves a request was sent even when a
            # private test exchange did not update its tracker.
            tracker.request_bytes_sent = True
            _validate_declared_response(status_code, headers, content)
            if self._monotonic() >= deadline:
                raise TaskTransportError(
                    "TASK_TIMEOUT",
                    status_code=status_code,
                    request_bytes_sent=True,
                    _retryable_transport=True,
                )
            return status_code, headers, content

        transport = _new_pinned_httpx_transport(
            address, tracker, deadline, self._monotonic
        )
        remaining = _remaining(deadline, self._monotonic)
        timeout = httpx.Timeout(
            connect=min(self.connect_timeout_seconds, remaining),
            read=min(self.read_timeout_seconds, remaining),
            write=min(self.write_timeout_seconds, remaining),
            pool=min(self.pool_timeout_seconds, remaining),
        )
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "ln-church-agent-task/1.17.0",
            "Connection": "close",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        if claim_token is not None:
            headers[TASK_CLAIM_HEADER] = claim_token

        client = httpx.Client(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
            headers={},
            cookies=None,
            auth=None,
        )
        try:
            with client.stream(
                method,
                TASK_API_ORIGIN + path,
                params=dict(params),
                headers=headers,
                content=body,
            ) as response:
                tracker.request_bytes_sent = True
                status_code = int(response.status_code)

                relevant: Dict[str, str] = {}
                counts: Dict[str, int] = {}
                try:
                    raw_items = response.headers.multi_items()
                except AttributeError:
                    raw_items = response.headers.items()
                for raw_name, raw_value in raw_items:
                    name = str(raw_name).strip().lower()
                    if name not in {
                        "content-encoding",
                        "content-length",
                        "retry-after",
                    }:
                        continue
                    counts[name] = counts.get(name, 0) + 1
                    if counts[name] > 1:
                        raise TaskTransportError(
                            "TASK_RESPONSE_INVALID",
                            status_code=status_code,
                            request_bytes_sent=True,
                        )
                    relevant[name] = str(raw_value).strip()

                content_encoding = relevant.get(
                    "content-encoding", ""
                ).lower()
                if content_encoding not in {"", "identity"}:
                    raise TaskTransportError(
                        "TASK_RESPONSE_ENCODING_REJECTED",
                        status_code=status_code,
                        request_bytes_sent=True,
                    )
                declared = relevant.get("content-length", "")
                if declared:
                    try:
                        declared_size = int(declared, 10)
                    except ValueError:
                        raise TaskTransportError(
                            "TASK_RESPONSE_INVALID",
                            status_code=status_code,
                            request_bytes_sent=True,
                        ) from None
                    if declared_size < 0:
                        raise TaskTransportError(
                            "TASK_RESPONSE_INVALID",
                            status_code=status_code,
                            request_bytes_sent=True,
                        )
                    if declared_size > TASK_MAX_JSON_BYTES:
                        raise TaskTransportError(
                            "TASK_RESPONSE_TOO_LARGE",
                            status_code=status_code,
                            request_bytes_sent=True,
                        )

                content = bytearray()
                for chunk in response.iter_raw():
                    _remaining(deadline, self._monotonic)
                    if len(content) + len(chunk) > TASK_MAX_JSON_BYTES:
                        raise TaskTransportError(
                            "TASK_RESPONSE_TOO_LARGE",
                            status_code=status_code,
                            request_bytes_sent=True,
                        )
                    content.extend(chunk)
                payload = bytes(content)
                _validate_declared_response(
                    status_code, relevant, payload
                )
                _remaining(deadline, self._monotonic)
                return status_code, relevant, payload
        finally:
            client.close()

    @_public_task_error_boundary
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        claim_token: Optional[str] = None,
        maximum_attempts: int = 1,
        ambiguous_delivery_code: Optional[str] = None,
        _total_timeout_seconds: Optional[float] = None,
        _exchange_budget: Optional[_TaskExchangeBudget] = None,
    ) -> TaskTransportResponse:
        if self._closed:
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            )
        operation = _classify_method_path(method, path)
        normalized_params = _validate_query(operation, params)
        body = _encode_body(operation, json_body)

        if operation in {"observation", "completion"}:
            try:
                claim_token = validate_claim_token(claim_token)
            except (TypeError, ValueError):
                raise TaskTransportError(
                    "TASK_CREDENTIAL_INVALID", request_bytes_sent=False
                ) from None
        elif claim_token is not None:
            raise TaskTransportError(
                "TASK_CREDENTIAL_INVALID", request_bytes_sent=False
            )

        allowed_attempts = {
            "list": 3,
            "detail": 3,
            "status": 3,
            "claim": 1,
            "observation": 2,
            "completion": 2,
        }[operation]
        if (
            type(maximum_attempts) is not int
            or not 1 <= maximum_attempts <= allowed_attempts
        ):
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            )
        if (
            _exchange_budget is not None
            and not isinstance(_exchange_budget, _TaskExchangeBudget)
        ):
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            )
        expected_ambiguity = {
            "claim": "CLAIM_OUTCOME_UNKNOWN",
            "observation": "SUBMISSION_OUTCOME_UNKNOWN",
            "completion": "COMPLETION_OUTCOME_UNKNOWN",
        }.get(operation)
        if ambiguous_delivery_code is not None and (
            ambiguous_delivery_code != expected_ambiguity
        ):
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            )

        operation_timeout = self.total_operation_timeout_seconds
        if _total_timeout_seconds is not None:
            if (
                isinstance(_total_timeout_seconds, bool)
                or not isinstance(_total_timeout_seconds, (int, float))
                or not math.isfinite(float(_total_timeout_seconds))
                or float(_total_timeout_seconds) <= 0.0
            ):
                raise TaskTransportError(
                    "TASK_TRANSPORT_ERROR", request_bytes_sent=False
                )
            operation_timeout = min(
                operation_timeout, float(_total_timeout_seconds)
            )
        try:
            deadline = float(self._monotonic()) + operation_timeout
        except Exception:
            raise TaskTransportError(
                "TASK_TRANSPORT_ERROR", request_bytes_sent=False
            ) from None

        last_error: Optional[TaskError] = None
        aggregate_request_state: Optional[bool] = False
        for attempt in range(maximum_attempts):
            tracker = _WriteTracker()
            try:
                if (
                    _exchange_budget is not None
                    and _exchange_budget.remaining <= 0
                ):
                    raise TaskTransportError(
                        "TASK_TIMEOUT", request_bytes_sent=False
                    )
                remaining = _remaining(deadline, self._monotonic)
                addresses = _resolve_addresses_bounded(
                    self._resolver, remaining
                )
                if _exchange_budget is not None:
                    _exchange_budget.consume()
                status, response_headers, content = self._exchange_once(
                    method=method,
                    path=path,
                    params=normalized_params,
                    body=body,
                    claim_token=claim_token,
                    address=addresses[0],
                    deadline=deadline,
                    tracker=tracker,
                )
                aggregate_request_state = _merge_request_byte_states(
                    aggregate_request_state, True
                )
                retry_after = _parse_retry_after(
                    response_headers.get("retry-after")
                )
                if 300 <= status <= 399:
                    raise TaskTransportError(
                        "TASK_REDIRECT_REJECTED",
                        status_code=status,
                        request_bytes_sent=True,
                    )
                if status == 402:
                    raise TaskTransportError(
                        "TASK_PAYMENT_UNEXPECTED",
                        status_code=status,
                        request_bytes_sent=True,
                    )
                if status in {502, 503, 504}:
                    raise TaskTransportError(
                        "TASK_TRANSPORT_ERROR",
                        status_code=status,
                        request_bytes_sent=True,
                        retry_after_seconds=retry_after,
                    )

                data = _decode_json_object(
                    status, response_headers, content
                )
                if status in _EXPECTED_SUCCESS_STATUSES:
                    return TaskTransportResponse(status, data)
                if 200 <= status <= 299:
                    raise TaskTransportError(
                        "TASK_RESPONSE_INVALID",
                        status_code=status,
                        request_bytes_sent=True,
                    )

                raise _validate_api_error(
                    operation, status, data, retry_after
                )
            except TaskError as exc:
                if exc.request_bytes_sent is None:
                    exc.request_bytes_sent = tracker.request_bytes_sent
                elif tracker.request_bytes_sent is True:
                    exc.request_bytes_sent = _merge_request_byte_states(
                        exc.request_bytes_sent, tracker.request_bytes_sent
                    )
                aggregate_request_state = _merge_request_byte_states(
                    aggregate_request_state, exc.request_bytes_sent
                )
                last_error = exc
            except Exception as exc:
                mapped = _map_exchange_exception(exc, tracker)
                aggregate_request_state = _merge_request_byte_states(
                    aggregate_request_state,
                    mapped.request_bytes_sent,
                )
                last_error = mapped

            if last_error is None:
                last_error = TaskTransportError(
                    "TASK_TRANSPORT_ERROR",
                    request_bytes_sent=tracker.request_bytes_sent,
                )
            if (
                attempt + 1 >= maximum_attempts
                or not _error_is_retryable(operation, last_error)
            ):
                break
            if (
                _exchange_budget is not None
                and _exchange_budget.remaining <= 0
            ):
                break
            backoff = (0.25, 0.5)[min(attempt, 1)]
            try:
                remaining = _remaining(deadline, self._monotonic)
            except TaskError:
                last_error = TaskTransportError(
                    "TASK_TIMEOUT",
                    request_bytes_sent=aggregate_request_state,
                    _retryable_transport=True,
                )
                break
            if backoff >= remaining:
                last_error = TaskTransportError(
                    "TASK_TIMEOUT",
                    request_bytes_sent=aggregate_request_state,
                    _retryable_transport=True,
                )
                break
            try:
                self._sleep(backoff)
            except Exception:
                last_error = TaskTransportError(
                    "TASK_TRANSPORT_ERROR",
                    request_bytes_sent=aggregate_request_state,
                )
                break

        if last_error is None:
            last_error = TaskTransportError(
                "TASK_TRANSPORT_ERROR",
                request_bytes_sent=aggregate_request_state,
            )
        last_error.request_bytes_sent = _merge_request_byte_states(
            aggregate_request_state, last_error.request_bytes_sent
        )
        if (
            ambiguous_delivery_code is not None
            and _ambiguity_required(operation, last_error)
        ):
            raise TaskAmbiguousOutcomeError(
                ambiguous_delivery_code,
                status_code=last_error.status_code,
                request_bytes_sent=last_error.request_bytes_sent,
                retry_after_seconds=last_error.retry_after_seconds,
            )
        raise last_error


__all__ = [
    "TASK_API_HOST",
    "TASK_API_ORIGIN",
    "TASK_API_PORT",
    "TASK_CLAIM_HEADER",
    "TASK_MAX_JSON_BYTES",
    "TaskAPIError",
    "TaskAmbiguousOutcomeError",
    "TaskError",
    "TaskTransport",
    "TaskTransportError",
    "TaskTransportResponse",
]
