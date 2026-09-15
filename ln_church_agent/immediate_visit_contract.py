"""Pure v1.18.3 wire validation; authority is the audited Wire/profile annex."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import math
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .task_contract import jcs_canonical_bytes
from .task_v2_contract import (
    PUBLIC_API_ORIGIN, PUBLIC_API_HOST, CLAIM_TOKEN_HEADER, IDEMPOTENCY_KEY_HEADER,
    validate_agent_id, validate_claim_token, validate_reward_address,
    validate_sha256, validate_submission_id, validate_task_id, validate_opaque_id,
    decode_json_object, task_detail_path, task_claim_path, task_abandon_path,
    task_completion_path, task_status_path,
)

TASK_TYPE = "immediate_http_visit.v1"
PROFILE_ID = "immediate_visit_utf8.v1"
TASK_DEFINITION_VERSION = "1.0.0"
TASK_SCHEMA_VERSION = "ln_church.agent_task.immediate_visit.v1"
TASK_PAGE_SCHEMA_VERSION = "ln_church.agent_task_page.immediate_visit.v1"
CLAIM_REQUEST_SCHEMA_VERSION = "ln_church.agent_task_claim_request.v1"
CLAIM_RESPONSE_SCHEMA_VERSION = "ln_church.agent_task_claim_response.immediate_visit.v1"
ABANDON_REQUEST_SCHEMA_VERSION = "ln_church.agent_task_abandon_request.immediate_visit.v1"
COMPLETION_SCHEMA_VERSION = "ln_church.task_completion.immediate_visit.v1"
COMPLETION_RECEIPT_SCHEMA_VERSION = "ln_church.task_completion_receipt.immediate_visit.v1"
STATUS_SCHEMA_VERSION = "ln_church.task_submission_status.immediate_visit.v1"
ERROR_SCHEMA_VERSION = "ln_church.task_error.immediate_visit.v1"
TASK_LIST_PATH = "/api/agent/tasks"
MAX_REPORT_BYTES = 65536
AGENT_REASONS = frozenset({
    "url_disallowed", "dns_failed", "dns_disallowed", "connection_failed",
    "peer_mismatch", "tls_failed", "fetch_timeout", "fetch_outcome_lost",
    "headers_limit_exceeded", "http_invalid", "content_encoding_unsupported",
    "body_limit_exceeded", "body_incomplete", "body_empty", "partial_response",
    "media_unsupported", "media_invalid", "charset_unsupported", "utf8_invalid",
    "html_structure_empty", "json_invalid", "json_depth_exceeded",
    "json_root_unsupported", "json_structure_unavailable",
})
STATUS_REASONS = AGENT_REASONS | frozenset({
    "reference_start_deadline", "reference_result_deadline", "reference_outcome_lost",
    "status", "media_family", "structure", "repeat_drop",
})
ERROR_CODES_BY_STATUS = {
    400: frozenset({"invalid_request", "unsupported_task_profile"}),
    401: frozenset({"invalid_claim_token"}),
    404: frozenset({"task_not_found", "not_found"}),
    409: frozenset({"listing_ended", "capacity_unavailable", "active_claim_exists",
                    "idempotency_conflict", "report_conflict", "claim_not_active",
                    "report_already_accepted"}),
    410: frozenset({"claim_expired"}),
}
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$")
_SERVER_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$")
_ENDPOINT = re.compile(r"^ep_[a-f0-9]{64}$")
_TX_HASH = re.compile(r"^0x[a-fA-F0-9]{64}$")


def validate_timestamp(value: Any, *, server: bool = False) -> str:
    pattern = _SERVER_TIMESTAMP if server else _TIMESTAMP
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("Invalid timestamp.")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("Invalid timestamp.") from None
    return value


def parse_timestamp(value: Any) -> datetime:
    return datetime.fromisoformat(validate_timestamp(value)[:-1] + "+00:00")


def validate_endpoint_id(value: Any) -> str:
    if not isinstance(value, str) or _ENDPOINT.fullmatch(value) is None:
        raise ValueError("Invalid endpoint_id.")
    return value


def validate_endpoint_url(value: Any) -> str:
    if (not isinstance(value, str) or not value.isascii() or len(value.encode("utf-8")) > 2048
            or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "#" in value or "\\" in value):
        raise ValueError("Invalid endpoint URL.")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        if (parts.scheme != "https" or not host or parts.netloc != host or host != host.lower()
                or "%" in host or parts.port is not None or parts.username is not None or parts.password is not None
                or not parts.path.startswith("/")
                or (urlunsplit(parts) != value and not (value.endswith("?") and urlunsplit(parts) + "?" == value))):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # WHATWG interprets a numeric terminal label as an IPv4 candidate.
            last = host.rstrip(".").rsplit(".", 1)[-1].lower()
            if last.isdecimal() or re.fullmatch(r"0x[0-9a-f]+", last):
                raise ValueError
        else:
            raise ValueError
        for part in parts.path.split("/"):
            if part.lower() in {".", "..", "%2e", "%2e%2e", ".%2e", "%2e."}:
                raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Invalid endpoint URL.") from None
    return value


def endpoint_id_for_url(url: str) -> str:
    return "ep_" + hashlib.sha256(validate_endpoint_url(url).encode("utf-8")).hexdigest()


def positive_bound(value: Any, name: str, *, integer: bool = False, maximum: Any = None) -> Any:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (integer and type(value) is not int)):
        raise ValueError("Invalid %s." % name)
    try:
        valid = math.isfinite(value) and value > 0 and (maximum is None or value <= maximum)
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        raise ValueError("Invalid %s." % name)
    return value


def canonical_report_bytes(value: Any) -> bytes:
    try:
        data = jcs_canonical_bytes(value)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Invalid immediate visit report.") from None
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Invalid immediate visit report.")
    return data


def validate_transaction_hash(value: Any) -> str:
    if not isinstance(value, str) or _TX_HASH.fullmatch(value) is None:
        raise ValueError("Invalid transaction hash.")
    return value
