"""Pure contract helpers for the v1.18 scheduled Task profile.

The v2 profile deliberately lives beside, rather than inside, the released
v1 Task contract.  This module has no transport or persistence behaviour.  It
only owns finite route constants, validation, canonical JSON, and validation
of the readiness-pinned Manifest bytes.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import pkgutil
import re
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

import idna

from .task_contract import (
    jcs_canonical_bytes,
    validate_reward_address as _validate_reward_address_v1,
    validate_task_id as _validate_task_id_v1,
)


CONTRACT_RESOURCE_PATH = "contracts/v18-scheduled-http-get-batch-contract-v1.json"
CONTRACT_FIXTURE_SHA256 = (
    "09eb478e30b56fec6efb462cfb43733b1e907bb247943f8fe6336af73d362785"
)
PUBLIC_API_ORIGIN = "https://kari.mayim-mayim.com"
PUBLIC_API_HOST = "kari.mayim-mayim.com"
TASK_TYPE = "scheduled_http_get_batch.v1"
TASK_DEFINITION_VERSION = "1.0.0"
TASK_SCHEMA_VERSION = "ln_church.agent_task.v2"
TASK_PAGE_SCHEMA_VERSION = "ln_church.agent_task_page.v1"
CLAIM_REQUEST_SCHEMA_VERSION = "ln_church.agent_task_claim_request.v1"
CLAIM_RESPONSE_SCHEMA_VERSION = "ln_church.agent_task_claim_response.v2"
READINESS_SCHEMA_VERSION = "ln_church.agent_task_readiness.v1"
ABANDON_REQUEST_SCHEMA_VERSION = "ln_church.agent_task_claim_abandon_request.v1"
MANIFEST_SCHEMA_VERSION = "ln_church.http_get_batch_manifest.v1"
COMPLETION_SCHEMA_VERSION = "ln_church.scheduled_http_get_batch_completion.v1"
COMPLETION_RECEIPT_SCHEMA_VERSION = "ln_church.agent_task_completion_receipt.v2"
REWARD_STATUS_SCHEMA_VERSION = "ln_church.agent_task_reward_status.v2"
ERROR_SCHEMA_VERSION = "ln_church.agent_task_error.v1"
CREDENTIAL_FILE_SCHEMA_VERSION = "ln_church.task_v2_claim_credential_file.v1"

CLAIM_TOKEN_HEADER = "X-LN-Task-Claim-Token"
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
TASK_LIST_PATH = "/api/agent/tasks"
TASK_LIST_QUERY = (
    "task_type=scheduled_http_get_batch.v1"
    "&task_schema_version=ln_church.agent_task.v2"
)
TASK_DETAIL_QUERY = "task_schema_version=ln_church.agent_task.v2"
TASK_DETAIL_PATH_TEMPLATE = "/api/agent/tasks/{task_id}"
TASK_CLAIM_PATH_TEMPLATE = "/api/agent/tasks/{task_id}/claim"
TASK_ABANDON_PATH_TEMPLATE = "/api/agent/tasks/{task_id}/claim/abandon"
TASK_READINESS_PATH_TEMPLATE = "/api/agent/tasks/{task_id}/readiness"
TASK_COMPLETION_PATH_TEMPLATE = "/api/agent/tasks/{task_id}/completion"
TASK_STATUS_PATH_TEMPLATE = (
    "/api/agent/tasks/{task_id}/submissions/{submission_id}/status"
)

MANIFEST_MAXIMUM_BYTES = 32768
MANIFEST_URL_MAXIMUM_BYTES = 2048
MANIFEST_MINIMUM_URLS = 1
MANIFEST_MAXIMUM_URLS = 10
COMPLETION_MAXIMUM_BYTES = 65536
REPORT_CLOSE_OFFSET_SECONDS = 600
NEW_TARGET_CLOSE_OFFSET_SECONDS = 300
MANIFEST_FETCH_MAXIMUM_ATTEMPTS = 3
MANIFEST_FETCH_OPERATION_DEADLINE_MS = 5000
MANIFEST_FETCH_ATTEMPT_TOTAL_TIMEOUT_MS = 1500

_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SUBMISSION_ID_RE = re.compile(r"^sub_[a-f0-9]{32}$")
_CLAIM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_RFC3339_WHOLE_SECOND_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$"
)
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_HOST_LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

MANIFEST_FETCH_OUTCOMES = frozenset(
    {
        "retrieved",
        "release_http_unexpected_status",
        "release_timeout",
        "release_dns_error",
        "release_tls_error",
        "release_connection_error",
        "release_protocol_error",
        "release_response_too_large",
        "release_encoding_unsupported",
        "release_invalid_json",
        "release_schema_invalid",
        "release_digest_mismatch",
        "release_interrupted",
    }
)
TARGET_OUTCOMES = frozenset(
    {
        "http_response",
        "dns_error",
        "tls_error",
        "connection_error",
        "timeout",
        "protocol_error",
        "interrupted_indeterminate",
        "not_attempted_interrupted",
        "not_attempted_deadline",
    }
)

V2_ERROR_CODES_BY_STATUS = {
    400: frozenset({"invalid_request", "invalid_manifest", "unsupported_task_type"}),
    401: frozenset({"invalid_control_key", "invalid_claim_token"}),
    403: frozenset({"origin_mismatch", "offer_not_manageable"}),
    404: frozenset({"not_found"}),
    409: frozenset(
        {
            "idempotency_conflict",
            "registration_intent_conflict",
            "payment_authorization_conflict",
            "campaign_capacity_unavailable",
            "offer_not_claimable",
            "wallet_guard_conflict",
            "claim_outcome_unknown",
            "submission_conflict",
            "offer_not_cancellable",
        }
    ),
    410: frozenset({"claim_expired", "report_closed"}),
    422: frozenset({"report_binding_invalid"}),
    425: frozenset({"report_not_open", "manifest_not_yet_available"}),
    503: frozenset({"settlement_reconciliation_pending", "temporarily_unavailable"}),
}


class ManifestContractError(ValueError):
    """Finite validation failure mapped directly to a report outcome."""

    def __init__(self, outcome: str) -> None:
        if outcome not in MANIFEST_FETCH_OUTCOMES or outcome == "retrieved":
            outcome = "release_schema_invalid"
        super().__init__(outcome)
        self.outcome = outcome


@dataclass(frozen=True)
class ValidatedManifest:
    """Immutable validated view while preserving the exact authoritative bytes."""

    raw_bytes: bytes
    sha256: str
    urls: Tuple[str, ...]


def load_contract_fixture_bytes() -> bytes:
    """Load and verify the one package-data mirror of the canonical fixture."""

    data = pkgutil.get_data("ln_church_agent", CONTRACT_RESOURCE_PATH)
    if data is None or not data.endswith(b"\n"):
        raise RuntimeError("Invalid v1.18 contract fixture.")
    if hashlib.sha256(data).hexdigest() != CONTRACT_FIXTURE_SHA256:
        raise RuntimeError("Invalid v1.18 contract fixture.")
    try:
        parsed = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError):
        raise RuntimeError("Invalid v1.18 contract fixture.") from None
    if not isinstance(parsed, dict):
        raise RuntimeError("Invalid v1.18 contract fixture.")
    return bytes(data)


def validate_task_id(value: Any) -> str:
    try:
        return _validate_task_id_v1(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid task_id.") from None


def validate_agent_id(value: Any) -> str:
    if not isinstance(value, str) or _AGENT_ID_RE.fullmatch(value) is None:
        raise ValueError("Invalid agent_id.")
    return value


def validate_reward_address(value: Any) -> str:
    try:
        return _validate_reward_address_v1(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid reward_address.") from None


def validate_sha256(value: Any, field_name: str = "sha256") -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError("Invalid %s." % field_name)
    return value


def validate_submission_id(value: Any) -> str:
    if not isinstance(value, str) or _SUBMISSION_ID_RE.fullmatch(value) is None:
        raise ValueError("Invalid submission_id.")
    return value


def validate_claim_token(value: Any) -> str:
    if not isinstance(value, str) or _CLAIM_TOKEN_RE.fullmatch(value) is None:
        raise ValueError("Invalid claim credential.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    except (UnicodeError, ValueError):
        raise ValueError("Invalid claim credential.") from None
    if len(decoded) != 32 or canonical != value:
        raise ValueError("Invalid claim credential.")
    return value


def validate_opaque_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        raise ValueError("Invalid %s." % field_name)
    return value


def validate_rfc3339_whole_second(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or _RFC3339_WHOLE_SECOND_RE.fullmatch(value) is None
    ):
        raise ValueError("Invalid %s." % field_name)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise ValueError("Invalid %s." % field_name) from None
    return value


def parse_rfc3339_whole_second(value: Any, field_name: str) -> datetime:
    validated = validate_rfc3339_whole_second(value, field_name)
    return datetime.strptime(validated, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def validate_elapsed_ms(value: Any, maximum: int, field_name: str) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ValueError("Invalid %s." % field_name)
    return value


def validate_amount_atomic(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        raise ValueError("Invalid amount_atomic.")
    return value


def _path(template: str, task_id: Any) -> str:
    return template.format(task_id=validate_task_id(task_id))


def task_detail_path(task_id: Any) -> str:
    return _path(TASK_DETAIL_PATH_TEMPLATE, task_id)


def task_claim_path(task_id: Any) -> str:
    return _path(TASK_CLAIM_PATH_TEMPLATE, task_id)


def task_abandon_path(task_id: Any) -> str:
    return _path(TASK_ABANDON_PATH_TEMPLATE, task_id)


def task_readiness_path(task_id: Any) -> str:
    return _path(TASK_READINESS_PATH_TEMPLATE, task_id)


def task_completion_path(task_id: Any) -> str:
    return _path(TASK_COMPLETION_PATH_TEMPLATE, task_id)


def task_status_path(task_id: Any, submission_id: Any) -> str:
    return TASK_STATUS_PATH_TEMPLATE.format(
        task_id=validate_task_id(task_id),
        submission_id=validate_submission_id(submission_id),
    )


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field.")
        result[key] = value
    return result


def decode_json_object(raw: bytes, maximum_bytes: int) -> Dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise ValueError("Invalid JSON response.")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (TypeError, UnicodeError, ValueError):
        raise ValueError("Invalid JSON response.") from None
    if type(value) is not dict:
        raise ValueError("Invalid JSON response.")
    return value


def validate_release_url(value: Any) -> str:
    """Validate without rebuilding or exposing the signed bearer URL."""

    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or len(value.encode("utf-8")) > 16384
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError("Invalid Manifest release URL.")
    try:
        parts = urlsplit(value)
        port = parts.port
    except (TypeError, ValueError):
        raise ValueError("Invalid Manifest release URL.") from None
    if (
        parts.scheme != "https"
        or parts.hostname != "tasks-release.mayim-mayim.com"
        or parts.netloc != "tasks-release.mayim-mayim.com"
        or port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or not parts.path.startswith("/")
        or not parts.query
        or parts.fragment
        or urlunsplit(parts) != value
    ):
        raise ValueError("Invalid Manifest release URL.")
    return value


def validate_canonical_target_url(value: Any) -> str:
    """Validate the Contract's canonical WHATWG-compatible HTTPS subset."""

    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or len(value.encode("utf-8")) > MANIFEST_URL_MAXIMUM_BYTES
        or "\\" in value
        or _PERCENT_ESCAPE_RE.search(value) is not None
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError("Invalid target URL.")
    try:
        parts = urlsplit(value)
        port = parts.port
    except (TypeError, ValueError):
        raise ValueError("Invalid target URL.") from None
    host = parts.hostname
    if (
        parts.scheme != "https"
        or not host
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or not parts.path.startswith("/")
        or port is not None
        or parts.netloc != host
        or host != host.lower()
        or host.endswith(".")
        or urlunsplit(parts) != value
    ):
        raise ValueError("Invalid target URL.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Invalid target URL.")
    try:
        if idna.encode(host, uts46=False).decode("ascii") != host:
            raise ValueError
    except (UnicodeError, ValueError, idna.IDNAError):
        raise ValueError("Invalid target URL.") from None
    labels = host.split(".")
    if len(host) > 253 or any(_HOST_LABEL_RE.fullmatch(label) is None for label in labels):
        raise ValueError("Invalid target URL.")
    # WHATWG removes dot path segments, including their percent-encoded forms.
    # The contract rejects inputs that would change under that serialization.
    for segment in parts.path.split("/"):
        dot_form = segment.lower()
        if dot_form in {".", "..", "%2e", "%2e%2e", ".%2e", "%2e."}:
            raise ValueError("Invalid target URL.")
    return value


def validate_manifest_bytes(raw: bytes, expected_sha256: Any) -> ValidatedManifest:
    """Validate exact server-canonical bytes before any target is accessible."""

    expected = validate_sha256(expected_sha256, "manifest_sha256")
    if not isinstance(raw, bytes) or len(raw) > MANIFEST_MAXIMUM_BYTES:
        raise ManifestContractError("release_response_too_large")
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected:
        raise ManifestContractError("release_digest_mismatch")
    try:
        value = decode_json_object(raw, MANIFEST_MAXIMUM_BYTES)
    except ValueError:
        raise ManifestContractError("release_invalid_json") from None
    if set(value.keys()) != {"schema_version", "method", "urls"}:
        raise ManifestContractError("release_schema_invalid")
    if (
        value.get("schema_version") != MANIFEST_SCHEMA_VERSION
        or value.get("method") != "GET"
        or type(value.get("urls")) is not list
    ):
        raise ManifestContractError("release_schema_invalid")
    urls_value = value["urls"]
    if not MANIFEST_MINIMUM_URLS <= len(urls_value) <= MANIFEST_MAXIMUM_URLS:
        raise ManifestContractError("release_schema_invalid")
    try:
        urls = tuple(validate_canonical_target_url(item) for item in urls_value)
    except (TypeError, ValueError):
        raise ManifestContractError("release_schema_invalid") from None
    if len(set(urls)) != len(urls):
        raise ManifestContractError("release_schema_invalid")
    origins = {(urlsplit(url).scheme, urlsplit(url).hostname, urlsplit(url).port or 443) for url in urls}
    if len(origins) != 1:
        raise ManifestContractError("release_schema_invalid")
    try:
        canonical = jcs_canonical_bytes(value)
    except (TypeError, ValueError):
        raise ManifestContractError("release_schema_invalid") from None
    if canonical != raw:
        raise ManifestContractError("release_schema_invalid")
    return ValidatedManifest(raw_bytes=bytes(raw), sha256=observed, urls=urls)


def canonical_completion_bytes(value: Any) -> bytes:
    try:
        data = jcs_canonical_bytes(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid Completion report.") from None
    if len(data) > COMPLETION_MAXIMUM_BYTES:
        raise ValueError("Invalid Completion report.")
    return data


def canonical_completion_digest(value: Any) -> str:
    return hashlib.sha256(canonical_completion_bytes(value)).hexdigest()
