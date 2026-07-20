"""Keyless, SSRF-safe transport for Inspect MCP and ``cli.inspect_url``.

The public inspect APIs intentionally expose no resolver, proxy, header, or
transport override.  Underscore-prefixed seams exist only so the offline test
suite can exercise policy decisions without contacting external services.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import queue
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable, Iterable, Optional, Tuple
from urllib.parse import unquote_to_bytes, urljoin, urlsplit, urlunsplit

import requests
import urllib3

from .navigation import FORBIDDEN_REDIRECT_PORTS
from .redaction import (
    _inspect_address_is_forbidden,
    _inspect_hostname_is_forbidden,
    redact_inspect_public_url,
)


MAX_INSPECT_BODY_BYTES = 1024 * 1024
MAX_INSPECT_REDIRECTS = 3
MAX_INSPECT_TIMEOUT_SECONDS = 30.0
CANONICAL_OBSERVATION_ENDPOINT = (
    "https://kari.mayim-mayim.com/api/agent/external/mcp-observe"
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEX = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class _CanonicalTarget:
    scheme: str
    host: str
    port: int
    origin: str
    url: str
    host_header: str
    addresses: Tuple[str, ...] = ()


class InspectTransportError(Exception):
    """Safe internal failure carrying only a stable stage and code."""

    def __init__(
        self,
        stage: str,
        code: str,
        public_url: str = "REDACTED",
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(code)
        self.stage = stage
        self.code = code
        self.public_url = public_url
        self.status_code = status_code


class _DeadlineBudget(float):
    """Remaining seconds paired with the caller's fixed real-clock deadline.

    It remains a ``float`` so existing private test seams observe the same
    timeout value, while production transport code can avoid creating a fresh
    deadline after an arbitrary scheduling pause.
    """

    def __new__(cls, seconds: float, absolute_deadline: float):
        instance = float.__new__(cls, seconds)
        instance.absolute_deadline = absolute_deadline
        return instance


class _DeadlineAbortController:
    """Abort an in-flight socket when one absolute deadline expires.

    ``requests``/urllib3 timeouts limit an individual blocking socket
    operation.  A peer can therefore keep status/header parsing alive by
    sending one byte before every read timeout.  The controller retains a
    duplicate of the connected socket and shuts down the shared connection at
    the wall-clock deadline.  ``socket.dup()`` is available on both Windows
    and POSIX and, unlike retaining the original Python object, remains usable
    after urllib3 detaches that object while wrapping it in ``SSLSocket``.

    The only helper thread is a daemon timer.  Network I/O remains on the
    calling thread, so a deadline never leaves an unbounded request worker or
    permits an observation POST to continue in the background.
    """

    def __init__(
        self,
        deadline: float,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.deadline = deadline
        self.monotonic = monotonic
        self._lock = threading.Lock()
        self._state = "active"
        self._abort_sockets = []
        self._timer: Optional[threading.Timer] = None

    @property
    def expired(self) -> bool:
        with self._lock:
            return self._state == "expired"

    @staticmethod
    def _close_socket(sock: socket.socket, *, abort: bool) -> None:
        if abort:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            sock.close()
        except OSError:
            pass

    def start(self) -> None:
        delay = self.deadline - self.monotonic()
        if delay <= 0.0:
            self.expire()
            return
        timer = threading.Timer(delay, self.expire)
        timer.name = "ln-church-inspect-deadline"
        timer.daemon = True
        with self._lock:
            if self._state != "active":
                return
            self._timer = timer
        timer.start()

    def track_connected_socket(self, connected: socket.socket) -> None:
        """Keep an abort handle for a socket returned by urllib3 connect."""
        try:
            duplicate = connected.dup()
        except OSError:
            if self.expired or self.monotonic() >= self.deadline:
                self._close_socket(connected, abort=True)
                raise socket.timeout("Inspect total deadline expired") from None
            raise

        should_abort = False
        with self._lock:
            if self._state == "active" and self.monotonic() < self.deadline:
                self._abort_sockets.append(duplicate)
            elif self._state == "expired" or self.monotonic() >= self.deadline:
                should_abort = True
            else:
                self._close_socket(duplicate, abort=False)
                return
        if should_abort:
            # Shutting down the duplicate aborts the same TCP connection even
            # if urllib3 has already detached/wrapped the original socket.
            self._close_socket(duplicate, abort=True)
            raise socket.timeout("Inspect total deadline expired")

    def expire(self) -> None:
        with self._lock:
            if self._state != "active":
                return
            self._state = "expired"
            sockets, self._abort_sockets = self._abort_sockets, []
        for sock in sockets:
            self._close_socket(sock, abort=True)

    def finish(self) -> None:
        """Cancel the watchdog and release duplicates without aborting."""
        with self._lock:
            if self._state == "active":
                self._state = "finished"
            timer, self._timer = self._timer, None
            sockets, self._abort_sockets = self._abort_sockets, []
        if timer is not None:
            timer.cancel()
        for sock in sockets:
            self._close_socket(sock, abort=False)


class _DeadlinePoolManager(urllib3.PoolManager):
    """Install connection classes that expose sockets to the watchdog."""

    def __init__(self, *args, deadline_controller, **kwargs) -> None:
        self._deadline_controller = deadline_controller
        super().__init__(*args, **kwargs)

    def _new_pool(self, scheme, host, port, request_context=None):
        pool = super()._new_pool(scheme, host, port, request_context)
        base_connection_class = pool.ConnectionCls
        controller = self._deadline_controller

        class _DeadlineConnection(base_connection_class):
            def _new_conn(self):
                connected = super()._new_conn()
                controller.track_connected_socket(connected)
                return connected

        pool.ConnectionCls = _DeadlineConnection
        return pool


class _DeadlineHTTPAdapter(requests.adapters.HTTPAdapter):
    """HTTP adapter whose active socket is governed by a total deadline."""

    def __init__(self, deadline_controller: _DeadlineAbortController) -> None:
        self.deadline_controller = deadline_controller
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = _DeadlinePoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            deadline_controller=self.deadline_controller,
            **pool_kwargs,
        )


class _PinnedHTTPSAdapter(requests.adapters.HTTPAdapter):
    """Connect to a vetted IP while authenticating the original hostname."""

    def __init__(
        self,
        server_hostname: str,
        deadline_controller: Optional[_DeadlineAbortController] = None,
    ) -> None:
        self.server_hostname = server_hostname
        self.deadline_controller = deadline_controller
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["server_hostname"] = self.server_hostname
        pool_kwargs["assert_hostname"] = self.server_hostname
        if self.deadline_controller is None:
            return super().init_poolmanager(
                connections,
                maxsize,
                block=block,
                **pool_kwargs,
            )
        self.poolmanager = _DeadlinePoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            deadline_controller=self.deadline_controller,
            **pool_kwargs,
        )


def _contains_raw_or_encoded_control(value: str) -> bool:
    for char in value:
        codepoint = ord(char)
        if codepoint <= 0x20 or 0x7F <= codepoint <= 0x9F:
            return True
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _HEX
            or value[index + 2] not in _HEX
        ):
            return True
        decoded = int(value[index + 1:index + 3], 16)
        if decoded < 0x20 or decoded == 0x7F or decoded == 0x5C:
            return True
        index += 3
    try:
        decoded_text = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return True
    if any(0x7F <= ord(char) <= 0x9F for char in decoded_text):
        return True
    return False


def _validate_timeout(timeout: Any) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise InspectTransportError("url_validation", "invalid_timeout")
    value = float(timeout)
    if (
        not math.isfinite(value)
        or value <= 0.0
        or value > MAX_INSPECT_TIMEOUT_SECONDS
    ):
        raise InspectTransportError("url_validation", "invalid_timeout")
    return value


def _validate_method(method: Any) -> str:
    if not isinstance(method, str) or method != method.strip():
        raise InspectTransportError("url_validation", "method_not_allowed")
    normalized = method.upper()
    if normalized not in {"GET", "HEAD"}:
        raise InspectTransportError("url_validation", "method_not_allowed")
    return normalized


def _canonicalize_hostname(raw_host: str) -> str:
    if not raw_host or "%" in raw_host:
        raise InspectTransportError("url_validation", "invalid_url")
    try:
        address = ipaddress.ip_address(raw_host)
    except ValueError:
        candidate = raw_host[:-1] if raw_host.endswith(".") else raw_host
        try:
            canonical = candidate.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            raise InspectTransportError("url_validation", "invalid_url") from None
        if not canonical or len(canonical) > 253:
            raise InspectTransportError("url_validation", "invalid_url")
        labels = canonical.split(".")
        if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
            raise InspectTransportError("url_validation", "invalid_url")
        if all(
            label.isdigit()
            or re.fullmatch(r"0x[0-9a-f]+", label) is not None
            for label in labels
        ):
            raise InspectTransportError("url_validation", "ambiguous_url")
        if _inspect_hostname_is_forbidden(canonical):
            raise InspectTransportError("url_validation", "forbidden_target")
        return canonical
    return address.compressed.lower()


def _canonicalize_target(url: Any) -> _CanonicalTarget:
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 8192
        or url != url.strip()
        or "\\" in url
        or _contains_raw_or_encoded_control(url)
    ):
        raise InspectTransportError("url_validation", "invalid_url")

    try:
        parsed = urlsplit(url)
        raw_host = parsed.hostname
        explicit_port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        raise InspectTransportError("url_validation", "invalid_url") from None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        raise InspectTransportError("url_validation", "invalid_url")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise InspectTransportError("url_validation", "userinfo_forbidden")
    if not raw_host:
        raise InspectTransportError("url_validation", "invalid_url")

    # Brackets are valid only for an actual IPv6 literal.  This prevents
    # IPvFuture-like or parser-dependent authorities from being rewritten as
    # ordinary DNS names.  An explicit empty port is ambiguous and rejected.
    raw_authority = parsed.netloc
    if raw_authority.startswith("["):
        try:
            ipaddress.IPv6Address(raw_host)
        except ValueError:
            raise InspectTransportError("url_validation", "ambiguous_url") from None
    elif "[" in raw_authority or "]" in raw_authority:
        raise InspectTransportError("url_validation", "ambiguous_url")
    if raw_authority.endswith(":"):
        raise InspectTransportError("url_validation", "ambiguous_url")

    host = _canonicalize_hostname(raw_host)
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    if port == 0 or port in FORBIDDEN_REDIRECT_PORTS:
        raise InspectTransportError("url_validation", "forbidden_port")

    display_host = "[%s]" % host if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = display_host if port == default_port else "%s:%d" % (display_host, port)
    path = parsed.path or "/"
    rebuilt = urlunsplit((scheme, authority, path, parsed.query, ""))

    # Requests is the wire client.  Canonicalize its path/query representation
    # once, then verify that the secondary parser cannot change the authority.
    prepared = requests.PreparedRequest()
    try:
        prepared.prepare_url(rebuilt, None)
        wire_url = str(prepared.url)
        reparsed = urlsplit(wire_url)
        reparsed_port = reparsed.port or default_port
    except Exception:
        raise InspectTransportError("url_validation", "invalid_url") from None
    if (
        reparsed.scheme.lower() != scheme
        or (reparsed.hostname or "").lower() != host
        or reparsed_port != port
        or reparsed.username is not None
        or reparsed.password is not None
        or reparsed.fragment
        or "\\" in wire_url
        or _contains_raw_or_encoded_control(wire_url)
    ):
        raise InspectTransportError("url_validation", "ambiguous_url")

    origin = "%s://%s" % (scheme, authority)
    return _CanonicalTarget(
        scheme=scheme,
        host=host,
        port=port,
        origin=origin,
        url=wire_url,
        host_header=authority,
    )


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
        raise InspectTransportError(
            "dns_validation",
            "dns_resolution_failed",
        ) from None
    addresses = tuple(sorted({str(record[4][0]) for record in records}))
    if not addresses:
        raise InspectTransportError("dns_validation", "dns_empty")
    return addresses


def _resolve_addresses_bounded(
    host: str,
    port: int,
    timeout: float,
) -> Tuple[str, ...]:
    """Bound the blocking stdlib resolver without exposing a public override."""
    join_timeout = float(timeout)
    if isinstance(timeout, _DeadlineBudget):
        join_timeout = timeout.absolute_deadline - time.monotonic()
    if join_timeout <= 0.0:
        raise InspectTransportError("dns_validation", "dns_resolution_timeout")

    result_queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result_queue.put((True, _resolve_addresses(host, port)))
        except BaseException as exc:  # contained and converted below
            result_queue.put((False, exc))

    worker = threading.Thread(
        target=resolve,
        name="ln-church-inspect-dns",
        daemon=True,
    )
    worker.start()
    if isinstance(timeout, _DeadlineBudget):
        join_timeout = max(
            0.0,
            timeout.absolute_deadline - time.monotonic(),
        )
    worker.join(join_timeout)
    if worker.is_alive():
        raise InspectTransportError("dns_validation", "dns_resolution_timeout")
    try:
        succeeded, value = result_queue.get_nowait()
    except queue.Empty:
        raise InspectTransportError("dns_validation", "dns_resolution_failed") from None
    if succeeded:
        return value
    if isinstance(value, InspectTransportError):
        raise value
    raise InspectTransportError("dns_validation", "dns_resolution_failed") from None


def _require_global_address(raw_address: str) -> str:
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError:
        raise InspectTransportError(
            "dns_validation",
            "dns_forbidden_address",
        ) from None

    canonical = address.compressed.lower()
    if _inspect_address_is_forbidden(address):
        raise InspectTransportError("dns_validation", "dns_forbidden_address")
    return canonical


def _validate_and_resolve(
    target: _CanonicalTarget,
    timeout: float = MAX_INSPECT_TIMEOUT_SECONDS,
) -> _CanonicalTarget:
    try:
        literal = ipaddress.ip_address(target.host)
    except ValueError:
        candidates = _resolve_addresses_bounded(target.host, target.port, timeout)
    else:
        candidates = (literal.compressed,)

    validated = tuple(sorted({_require_global_address(value) for value in candidates}))
    if not validated:
        raise InspectTransportError("dns_validation", "dns_empty")
    return _CanonicalTarget(
        scheme=target.scheme,
        host=target.host,
        port=target.port,
        origin=target.origin,
        url=target.url,
        host_header=target.host_header,
        addresses=validated,
    )


def _pinned_url(target: _CanonicalTarget, address: str) -> str:
    display = "[%s]" % address if ":" in address else address
    default_port = 443 if target.scheme == "https" else 80
    authority = display if target.port == default_port else "%s:%d" % (display, target.port)
    parsed = urlsplit(target.url)
    return urlunsplit((target.scheme, authority, parsed.path, parsed.query, ""))


def _fixed_headers(target: _CanonicalTarget, has_body: bool) -> dict:
    headers = {
        "Host": target.host_header,
        "User-Agent": "ln-church-agent-inspect/1.16.4",
        "Accept": "application/json, */*;q=0.1",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if has_body:
        headers["Content-Type"] = "application/json"
    return headers


def _remaining(deadline: float, monotonic: Callable[[], float]) -> float:
    value = deadline - monotonic()
    if value <= 0.0:
        raise InspectTransportError("transport", "transport_timeout")
    return value


def _remaining_budget(
    deadline: float,
    monotonic: Callable[[], float],
) -> _DeadlineBudget:
    """Translate one outer deadline without extending it between call frames."""
    real_started = time.monotonic()
    seconds = _remaining(deadline, monotonic)
    return _DeadlineBudget(seconds, real_started + seconds)


def _set_stream_read_timeout(response: requests.Response, timeout: float) -> None:
    """Best-effort tightening of urllib3's socket to the total deadline."""
    candidates = []
    try:
        candidates.append(response.raw._connection.sock)
    except (AttributeError, TypeError):
        pass
    try:
        candidates.append(response.raw._fp.fp.raw._sock)
    except (AttributeError, TypeError):
        pass
    for candidate in candidates:
        if candidate is not None and hasattr(candidate, "settimeout"):
            try:
                candidate.settimeout(timeout)
                return
            except (OSError, ValueError):
                continue


def _read_bounded_body(
    response: requests.Response,
    deadline: Optional[float] = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    content_encoding = str(response.headers.get("Content-Encoding", "")).strip().lower()
    if content_encoding not in {"", "identity"}:
        response.close()
        raise InspectTransportError(
            "response_limit",
            "compressed_response_rejected",
        )

    content_length = str(response.headers.get("Content-Length", "")).strip()
    if content_length:
        try:
            declared_length = int(content_length, 10)
        except ValueError:
            response.close()
            raise InspectTransportError(
                "response_limit",
                "invalid_content_length",
            ) from None
        if declared_length < 0:
            response.close()
            raise InspectTransportError(
                "response_limit",
                "invalid_content_length",
            )
        if declared_length > MAX_INSPECT_BODY_BYTES:
            response.close()
            raise InspectTransportError(
                "response_limit",
                "response_too_large",
            )

    content = bytearray()
    try:
        raw = response.raw
        try:
            raw.decode_content = False
        except (AttributeError, TypeError):
            pass
        while True:
            if deadline is not None:
                _set_stream_read_timeout(
                    response,
                    _remaining(deadline, monotonic),
                )
            remaining = MAX_INSPECT_BODY_BYTES - len(content)
            amount = 1 if remaining == 0 else min(64 * 1024, remaining)
            chunk = raw.read(amount, decode_content=False)
            if not chunk:
                break
            if len(chunk) > remaining:
                raise InspectTransportError(
                    "response_limit",
                    "response_too_large",
                )
            content.extend(chunk)
    except InspectTransportError:
        response.close()
        raise
    except (
        requests.exceptions.Timeout,
        urllib3.exceptions.ReadTimeoutError,
        socket.timeout,
    ):
        response.close()
        raise InspectTransportError("transport", "transport_timeout") from None
    except (
        requests.exceptions.SSLError,
        urllib3.exceptions.SSLError,
        ssl.SSLError,
    ):
        response.close()
        raise InspectTransportError("transport", "tls_verification_failed") from None
    except Exception:
        response.close()
        raise InspectTransportError("transport", "network_error") from None

    response._content = bytes(content)
    response._content_consumed = True


def _exchange_once(
    target: _CanonicalTarget,
    address: str,
    method: str,
    timeout: float,
    body: Optional[bytes] = None,
) -> requests.Response:
    """Private test seam: perform one request to one already-vetted IP."""

    deadline = (
        timeout.absolute_deadline
        if isinstance(timeout, _DeadlineBudget)
        else time.monotonic() + float(timeout)
    )
    controller = _DeadlineAbortController(deadline)
    controller.start()
    session: Optional[requests.Session] = None
    response: Optional[requests.Response] = None
    try:
        session = requests.Session()
        session.trust_env = False
        session.headers.clear()
        session.cookies.clear()
        transport_url = _pinned_url(target, address)
        if target.scheme == "https":
            session.mount(
                "https://",
                _PinnedHTTPSAdapter(target.host, controller),
            )
        else:
            session.mount("http://", _DeadlineHTTPAdapter(controller))
        response = session.request(
            method,
            transport_url,
            headers=_fixed_headers(target, body is not None),
            data=body,
            timeout=_remaining(deadline, time.monotonic),
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        if controller.expired or time.monotonic() >= deadline:
            response.close()
            raise InspectTransportError("transport", "transport_timeout")
        _read_bounded_body(response, deadline)
        if controller.expired or time.monotonic() >= deadline:
            response.close()
            raise InspectTransportError("transport", "transport_timeout")
        response.url = target.url
        return response
    except InspectTransportError as exc:
        if (
            exc.code != "transport_timeout"
            and (controller.expired or time.monotonic() >= deadline)
        ):
            if response is not None:
                response.close()
            raise InspectTransportError("transport", "transport_timeout") from None
        raise
    except requests.exceptions.Timeout:
        raise InspectTransportError("transport", "transport_timeout") from None
    except requests.exceptions.SSLError:
        if controller.expired or time.monotonic() >= deadline:
            raise InspectTransportError("transport", "transport_timeout") from None
        raise InspectTransportError("transport", "tls_verification_failed") from None
    except requests.exceptions.RequestException:
        if controller.expired or time.monotonic() >= deadline:
            raise InspectTransportError("transport", "transport_timeout") from None
        raise InspectTransportError("transport", "network_error") from None
    except Exception:
        if controller.expired or time.monotonic() >= deadline:
            raise InspectTransportError("transport", "transport_timeout") from None
        raise InspectTransportError("transport", "network_error") from None
    finally:
        if session is not None:
            session.close()
        controller.finish()


def _exchange_observation_once(
    target: _CanonicalTarget,
    address: str,
    timeout: float,
    body: bytes,
) -> int:
    """POST once to one vetted IP and consume no response body.

    A POST whose outcome is uncertain is never replayed against another DNS
    answer.  Returning only the status also keeps response body access out of
    the observation call graph by construction.
    """
    deadline = (
        timeout.absolute_deadline
        if isinstance(timeout, _DeadlineBudget)
        else time.monotonic() + float(timeout)
    )
    controller = _DeadlineAbortController(deadline)
    controller.start()
    session: Optional[requests.Session] = None
    response: Optional[requests.Response] = None
    try:
        session = requests.Session()
        session.trust_env = False
        session.headers.clear()
        session.cookies.clear()
        transport_url = _pinned_url(target, address)
        if target.scheme == "https":
            session.mount(
                "https://",
                _PinnedHTTPSAdapter(target.host, controller),
            )
        else:
            session.mount("http://", _DeadlineHTTPAdapter(controller))
        response = session.request(
            "POST",
            transport_url,
            headers=_fixed_headers(target, True),
            data=body,
            timeout=_remaining(deadline, time.monotonic),
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        if controller.expired or time.monotonic() >= deadline:
            raise InspectTransportError(
                "transport",
                "observation_delivery_unknown",
            )
        return int(response.status_code)
    except InspectTransportError:
        raise
    except (requests.exceptions.Timeout, requests.exceptions.RequestException):
        raise InspectTransportError(
            "transport",
            "observation_delivery_unknown",
        ) from None
    except Exception:
        raise InspectTransportError(
            "transport",
            "observation_delivery_unknown",
        ) from None
    finally:
        if response is not None:
            response.close()
        if session is not None:
            session.close()
        controller.finish()


def _request_target(
    target: _CanonicalTarget,
    method: str,
    deadline: float,
    monotonic: Callable[[], float],
    body: Optional[bytes] = None,
) -> requests.Response:
    last_error: Optional[InspectTransportError] = None
    for address in target.addresses:
        try:
            response = _exchange_once(
                target,
                address,
                method,
                _remaining_budget(deadline, monotonic),
                body,
            )
            response.url = target.url
            return response
        except InspectTransportError as exc:
            if exc.stage == "response_limit" or exc.code not in {
                "network_error",
                "transport_timeout",
                "tls_verification_failed",
            }:
                raise
            last_error = exc
        except requests.exceptions.Timeout:
            last_error = InspectTransportError("transport", "transport_timeout")
        except requests.exceptions.SSLError:
            last_error = InspectTransportError("transport", "tls_verification_failed")
        except Exception:
            last_error = InspectTransportError("transport", "network_error")
    if last_error is None:
        raise InspectTransportError("transport", "network_error")
    raise last_error


def _inspect_request_with_clock(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
    *,
    monotonic: Callable[[], float],
) -> requests.Response:
    normalized_method = _validate_method(method)
    timeout_value = _validate_timeout(timeout)
    initial = _canonicalize_target(url)
    initial_public_url = redact_inspect_public_url(initial.url)
    deadline = monotonic() + timeout_value
    try:
        current = _validate_and_resolve(
            initial,
            _remaining_budget(deadline, monotonic),
        )
    except InspectTransportError as exc:
        if exc.code in {"dns_resolution_timeout", "transport_timeout"}:
            raise InspectTransportError(
                "transport",
                "transport_timeout",
                initial_public_url,
            ) from None
        raise
    visited = {current.url}
    redirects_followed = 0

    while True:
        try:
            response = _request_target(
                current,
                normalized_method,
                deadline,
                monotonic,
            )
        except InspectTransportError as exc:
            exc.public_url = initial_public_url
            raise

        status = int(response.status_code)
        if status in _REDIRECT_STATUSES:
            if redirects_followed >= MAX_INSPECT_REDIRECTS:
                response.close()
                raise InspectTransportError(
                    "redirect_validation",
                    "redirect_limit_exceeded",
                    initial_public_url,
                )
            location = response.headers.get("Location")
            response.close()
            if not isinstance(location, str) or not location.strip():
                raise InspectTransportError(
                    "redirect_validation",
                    "redirect_invalid",
                    initial_public_url,
                )
            if (
                len(location) > 8192
                or location != location.strip()
                or "\\" in location
                or _contains_raw_or_encoded_control(location)
            ):
                raise InspectTransportError(
                    "redirect_validation",
                    "redirect_invalid",
                    initial_public_url,
                )
            try:
                parsed_location = urlsplit(location)
                if parsed_location.scheme and not parsed_location.netloc:
                    raise ValueError("absolute redirect without authority")
                joined = urljoin(current.url, location)
                next_target = _canonicalize_target(joined)
            except (InspectTransportError, TypeError, ValueError, UnicodeError):
                raise InspectTransportError(
                    "redirect_validation",
                    "redirect_invalid",
                    initial_public_url,
                ) from None
            if current.scheme == "https" and next_target.scheme != "https":
                raise InspectTransportError(
                    "redirect_validation",
                    "https_downgrade_forbidden",
                    initial_public_url,
                )
            if next_target.url in visited:
                raise InspectTransportError(
                    "redirect_validation",
                    "redirect_loop",
                    initial_public_url,
                )
            try:
                current = _validate_and_resolve(
                    next_target,
                    _remaining_budget(deadline, monotonic),
                )
            except InspectTransportError as exc:
                if exc.code in {
                    "dns_resolution_timeout",
                    "transport_timeout",
                } or monotonic() >= deadline:
                    raise InspectTransportError(
                        "transport",
                        "transport_timeout",
                        initial_public_url,
                    ) from None
                raise InspectTransportError(
                    "redirect_validation",
                    "redirect_target_forbidden",
                    initial_public_url,
                ) from None
            visited.add(current.url)
            redirects_followed += 1
            continue
        if 300 <= status < 400:
            response.close()
            raise InspectTransportError(
                "redirect_validation",
                "redirect_invalid",
                initial_public_url,
            )
        response.url = current.url
        return response


def _inspect_request(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
) -> requests.Response:
    """Fetch one public HTTP(S) target under the fixed Inspect policy."""
    return _inspect_request_with_clock(
        url,
        method,
        timeout,
        monotonic=time.monotonic,
    )


def _submit_observation_request_with_clock(
    endpoint: str,
    payload_json: bytes,
    timeout: float = 5.0,
    *,
    monotonic: Callable[[], float],
) -> int:
    if endpoint != CANONICAL_OBSERVATION_ENDPOINT:
        raise InspectTransportError(
            "url_validation",
            "observation_endpoint_mismatch",
        )
    timeout_value = _validate_timeout(timeout)
    deadline = monotonic() + timeout_value
    target = _validate_and_resolve(
        _canonicalize_target(endpoint),
        _remaining_budget(deadline, monotonic),
    )
    # Deliberately select one deterministic vetted address.  POST is not sent
    # through the GET/HEAD multi-address retry path because the first delivery
    # may have succeeded even when its response is lost.
    status_code = _exchange_observation_once(
        target,
        target.addresses[0],
        _remaining_budget(deadline, monotonic),
        payload_json,
    )
    if 300 <= status_code < 400:
        raise InspectTransportError(
            "redirect_validation",
            "observation_redirect_rejected",
            status_code=status_code,
        )
    return status_code


def _submit_observation_request(
    endpoint: str,
    payload_json: bytes,
    timeout: float = 5.0,
) -> int:
    """POST an already-validated observation to the canonical endpoint."""
    return _submit_observation_request_with_clock(
        endpoint,
        payload_json,
        timeout,
        monotonic=time.monotonic,
    )


def _validate_observation_target(
    target_url: str,
    timeout: float = 5.0,
) -> None:
    """Recheck that a reported target currently resolves only to public IPs."""
    timeout_value = _validate_timeout(timeout)
    _validate_and_resolve(
        _canonicalize_target(target_url),
        timeout_value,
    )
