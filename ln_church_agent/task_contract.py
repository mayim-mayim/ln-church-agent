"""Fixed public wire contract helpers for the v1.17.0 Agent Task client.

This module deliberately contains no transport or payment behavior.  It
centralizes the finite constants and pure validation/canonicalization routines
shared by the public Task models and the keyless Task client.
"""

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import unquote_to_bytes, urlsplit

import idna


CONTRACT_ID = "ln_church.agent_task_venue.v1"
PUBLIC_API_ORIGIN = "https://kari.mayim-mayim.com"
TASK_TYPE_PAYMENT_SURFACE_DISCOVERY = "payment_surface_discovery.v1"
CLAIM_TOKEN_HEADER = "X-LN-Task-Claim-Token"
CLAIM_TOKEN_DOMAIN_SEPARATOR = b"ln_church.task_claim_token.v1\x00"
CLAIM_TOKEN_ENCODED_LENGTH = 43
CLAIM_TOKEN_BYTE_LENGTH = 32
CLAIM_LEASE_DURATION_SECONDS = 3600

TASK_LIST_PATH = "/api/agent/tasks"
TASK_DETAIL_PATH_TEMPLATE = "/api/agent/tasks/{task_id}"
TASK_SUBMISSION_STATUS_PATH_TEMPLATE = (
    "/api/agent/tasks/{task_id}/submissions/{submission_id}/status"
)
TASK_CLAIM_PATH_TEMPLATE = "/api/agent/tasks/{task_id}/claim"
TASK_OBSERVATION_PATH_TEMPLATE = (
    "/api/agent/tasks/{task_id}/domain-observations"
)
TASK_COMPLETION_PATH_TEMPLATE = "/api/agent/tasks/{task_id}/completion"

TASK_SCHEMA_VERSION = "ln_church.agent_task.v1"
TASK_PAGE_SCHEMA_VERSION = "ln_church.agent_task_page.v1"
CLAIM_REQUEST_SCHEMA_VERSION = "ln_church.agent_task_claim_request.v1"
CLAIM_RESPONSE_SCHEMA_VERSION = "ln_church.agent_task_claim_response.v1"
OBSERVATION_SUBMISSION_SCHEMA_VERSION = (
    "ln_church.task_domain_observation_submission.v1"
)
OBSERVATION_RESPONSE_SCHEMA_VERSION = (
    "ln_church.task_domain_observation_response.v1"
)
COMPLETION_REQUEST_SCHEMA_VERSION = (
    "ln_church.agent_task_completion_request.v1"
)
COMPLETION_RESPONSE_SCHEMA_VERSION = (
    "ln_church.agent_task_completion_response.v1"
)
REWARD_STATUS_SCHEMA_VERSION = "ln_church.agent_task_reward_status.v1"
CREDENTIAL_FILE_SCHEMA_VERSION = (
    "ln_church.task_claim_credential_file.v1"
)
ERROR_SCHEMA_VERSION = "ln_church.agent_task_error.v1"

REWARD_NETWORK = "eip155:8453"
REWARD_ASSET = "USDC"
REWARD_ASSET_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

TASK_OFFER_STATUSES = ("OPEN",)
CLAIM_RESPONSE_STATUSES = ("CLAIMED",)
PUBLIC_SUBMISSION_STATUSES = (
    "SUBMITTED",
    "EVALUATION_REJECTED",
    "REWARD_PENDING",
    "REWARDED",
    "REWARD_FAILED",
    "REWARD_AMBIGUOUS",
)
PRIVATE_EXECUTION_STATUSES = ("EXPIRED", "ABANDONED")

# Backward-compatible name for the public Task Offer status scope.  Execution
# statuses intentionally do not share this collection.
TASK_STATUSES = TASK_OFFER_STATUSES
REWARD_STATE_BY_TASK_STATUS = {
    "SUBMITTED": "pending",
    "EVALUATION_REJECTED": "not_eligible",
    "REWARD_PENDING": "approved_pending",
    "REWARDED": "paid",
    "REWARD_FAILED": "failed",
    "REWARD_AMBIGUOUS": "ambiguous",
}
EVALUATION_REJECTION_FAILURE_CODES = frozenset(
    {
        "observation_not_found",
        "claim_task_or_observation_binding_mismatch",
        "declared_agent_id_mismatch",
        "proven_observation_reuse",
    }
)
REWARD_FAILURE_CODES = frozenset(
    {
        "settlement_retry_exhausted",
        "settlement_conflict",
        "settlement_lease_expired",
        "settlement_unavailable",
    }
)
REWARD_AMBIGUOUS_FAILURE_CODES = frozenset({"settlement_ambiguous"})
FAILURE_CODES_BY_TASK_STATUS = {
    "SUBMITTED": frozenset(),
    "EVALUATION_REJECTED": EVALUATION_REJECTION_FAILURE_CODES,
    "REWARD_PENDING": frozenset(),
    "REWARDED": frozenset(),
    "REWARD_FAILED": REWARD_FAILURE_CODES,
    "REWARD_AMBIGUOUS": REWARD_AMBIGUOUS_FAILURE_CODES,
}
PUBLIC_SUBMISSION_FAILURE_CODES = frozenset(
    code
    for codes in FAILURE_CODES_BY_TASK_STATUS.values()
    for code in codes
)

DEFAULT_TASK_LIST_LIMIT = 20
MINIMUM_TASK_LIST_LIMIT = 1
MAXIMUM_TASK_LIST_LIMIT = 50
DEFAULT_TASK_DETAIL_LIMIT = 20
MINIMUM_TASK_DETAIL_LIMIT = 1
MAXIMUM_TASK_DETAIL_LIMIT = 50
MAXIMUM_OBSERVED_URLS = 50
MAXIMUM_DISCOVERED_SURFACES = 50
MAXIMUM_OBSERVATION_ERRORS = 20
MAXIMUM_URL_UTF8_BYTES = 2048
MAXIMUM_JSON_BYTES = 256 * 1024
MAXIMUM_CURSOR_UTF8_BYTES = 2048

CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 10
WRITE_TIMEOUT_SECONDS = 10
POOL_TIMEOUT_SECONDS = 5
TOTAL_OPERATION_TIMEOUT_SECONDS = 20

LIST_DETAIL_MAXIMUM_ATTEMPTS = 3
CLAIM_MAXIMUM_ATTEMPTS = 1
OBSERVATION_MAXIMUM_ATTEMPTS = 2
COMPLETION_MAXIMUM_ATTEMPTS = 2
LIST_DETAIL_BACKOFF_SECONDS = (0.25, 0.5)
RETRYABLE_HTTP_STATUSES = frozenset({429, 502, 503, 504})

REWARD_POLL_DEFAULT_TIMEOUT_SECONDS = 300
REWARD_POLL_MAXIMUM_ATTEMPTS = 10
REWARD_POLL_INITIAL_BACKOFF_SECONDS = 1
REWARD_POLL_MAXIMUM_BACKOFF_SECONDS = 30
REWARD_POLL_MAXIMUM_JITTER_SECONDS = 0.25
REWARD_POLL_MAXIMUM_RETRY_AFTER_SECONDS = 30

PUBLIC_ERROR_CODES_BY_STATUS = {
    400: frozenset(
        {"invalid_request", "unsupported_task_type", "domain_mismatch"}
    ),
    401: frozenset({"claim_token_invalid"}),
    404: frozenset({"task_not_found"}),
    409: frozenset(
        {"task_not_open", "task_state_conflict", "submission_conflict"}
    ),
    410: frozenset({"claim_lease_expired"}),
    413: frozenset({"payload_too_large"}),
    429: frozenset({"rate_limited"}),
    500: frozenset({"internal_error"}),
}
PUBLIC_ERROR_CODES = frozenset(
    code
    for codes in PUBLIC_ERROR_CODES_BY_STATUS.values()
    for code in codes
)
MUTATION_FREE_CLAIM_ERROR_CODES_BY_STATUS = {
    400: frozenset({"invalid_request"}),
    404: frozenset({"task_not_found"}),
    409: frozenset({"task_not_open", "task_state_conflict"}),
    429: frozenset({"rate_limited"}),
}
LOCAL_AMBIGUOUS_DELIVERY_CODES = (
    "CLAIM_OUTCOME_UNKNOWN",
    "SUBMISSION_OUTCOME_UNKNOWN",
    "COMPLETION_OUTCOME_UNKNOWN",
)
LOCAL_ERROR_CODES = (
    "TASK_ORIGIN_INVALID",
    "TASK_DNS_POLICY_REJECTED",
    "TASK_TLS_ERROR",
    "TASK_TIMEOUT",
    "TASK_TRANSPORT_ERROR",
    "TASK_REDIRECT_REJECTED",
    "TASK_PAYMENT_UNEXPECTED",
    "TASK_RESPONSE_ENCODING_REJECTED",
    "TASK_RESPONSE_TOO_LARGE",
    "TASK_RESPONSE_INVALID",
    "TASK_API_ERROR",
    "TASK_CREDENTIAL_INVALID",
    "TASK_CREDENTIAL_EXPIRED",
)

TASK_ID_PATTERN = r"^[A-Za-z0-9._~-]{1,128}$"
OBSERVATION_ID_PATTERN = TASK_ID_PATTERN
SUBMISSION_ID_PATTERN = r"^sub_[a-f0-9]{32}$"
AGENT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"

_TASK_ID_RE = re.compile(TASK_ID_PATTERN)
_OBSERVATION_ID_RE = re.compile(OBSERVATION_ID_PATTERN)
_SUBMISSION_ID_RE = re.compile(SUBMISSION_ID_PATTERN)
_AGENT_ID_RE = re.compile(AGENT_ID_PATTERN)
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CLAIM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9A-Fa-f]{40}$")
_TRANSACTION_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_AMOUNT_ATOMIC_RE = re.compile(r"^[1-9][0-9]*$")
_RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(?:\.\d{1,9})?Z$"
)
_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

_NON_PUBLIC_SUFFIXES = {
    "arpa",
    "example",
    "home",
    "internal",
    "invalid",
    "lan",
    "local",
    "localhost",
    "onion",
    "test",
}


def _invalid(field_name: str) -> ValueError:
    """Return a finite validation error that never embeds untrusted input."""

    return ValueError("Invalid %s." % field_name)


def validate_nfc_string(
    value: Any,
    field_name: str = "string",
    minimum_utf8_bytes: int = 0,
    maximum_utf8_bytes: Optional[int] = None,
) -> str:
    """Require an already-NFC Unicode string without control characters."""

    if not isinstance(value, str):
        raise _invalid(field_name)
    if unicodedata.normalize("NFC", value) != value:
        raise _invalid(field_name)
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise _invalid(field_name)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise _invalid(field_name) from None
    if len(encoded) < minimum_utf8_bytes:
        raise _invalid(field_name)
    if maximum_utf8_bytes is not None and len(encoded) > maximum_utf8_bytes:
        raise _invalid(field_name)
    return value


def validate_task_id(value: Any) -> str:
    value = validate_nfc_string(value, "task_id", minimum_utf8_bytes=1)
    if _TASK_ID_RE.fullmatch(value) is None:
        raise _invalid("task_id")
    return value


def validate_observation_id(value: Any) -> str:
    value = validate_nfc_string(value, "observation_id", minimum_utf8_bytes=1)
    if _OBSERVATION_ID_RE.fullmatch(value) is None:
        raise _invalid("observation_id")
    return value


def validate_submission_id(value: Any) -> str:
    value = validate_nfc_string(value, "submission_id", minimum_utf8_bytes=1)
    if _SUBMISSION_ID_RE.fullmatch(value) is None:
        raise _invalid("submission_id")
    return value


def validate_task_definition_version(value: Any) -> str:
    """Validate the opaque Task Definition version without interpreting it."""

    return validate_nfc_string(
        value,
        "task_definition_version",
        minimum_utf8_bytes=1,
    )


def _validate_sha256_hex(value: Any, field_name: str) -> str:
    value = validate_nfc_string(
        value,
        field_name,
        minimum_utf8_bytes=64,
        maximum_utf8_bytes=64,
    )
    if _SHA256_HEX_RE.fullmatch(value) is None:
        raise _invalid(field_name)
    return value


def validate_task_definition_digest(value: Any) -> str:
    return _validate_sha256_hex(value, "task_definition_digest")


def validate_manifest_sha256(value: Any) -> str:
    return _validate_sha256_hex(value, "manifest_sha256")


def validate_manifest_url(value: Any) -> str:
    """Require and retain an exact absolute HTTPS Task Definition URL.

    The value is deliberately returned byte-for-byte as supplied.  This
    validator does not construct a registry key, resolve a mutable alias, or
    fetch the referenced object.
    """

    value = validate_nfc_string(
        value,
        "manifest_url",
        minimum_utf8_bytes=1,
    )
    if not value.startswith("https://"):
        raise _invalid("manifest_url")
    if "\\" in value or any(char.isspace() for char in value):
        raise _invalid("manifest_url")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise _invalid("manifest_url") from None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise _invalid("manifest_url")
    if port is not None and not (1 <= port <= 65535):
        raise _invalid("manifest_url")
    return value


def generate_submission_id() -> str:
    """Create the fixed v1 submission identifier from 128 CSPRNG bits."""

    return "sub_" + secrets.token_hex(16)


def validate_agent_id(value: Any) -> str:
    value = validate_nfc_string(value, "agent_id", minimum_utf8_bytes=1)
    if _AGENT_ID_RE.fullmatch(value) is None:
        raise _invalid("agent_id")
    return value


def validate_cursor(value: Any) -> str:
    """Validate an opaque cursor without interpreting or normalizing it."""

    return validate_nfc_string(
        value,
        "cursor",
        minimum_utf8_bytes=1,
        maximum_utf8_bytes=MAXIMUM_CURSOR_UTF8_BYTES,
    )


def validate_public_domain(value: Any, field_name: str = "domain") -> str:
    """Require a lowercase, public-looking IDNA A-label domain.

    Network routability remains a per-request transport check.  This pure
    validator rejects IP literals, local-use suffixes, Unicode/U-label input,
    URLs, trailing dots, and non-canonical DNS labels.
    """

    value = validate_nfc_string(
        value, field_name, minimum_utf8_bytes=1, maximum_utf8_bytes=253
    )
    if value != value.lower() or value.endswith(".") or not value.isascii():
        raise _invalid(field_name)
    if any(char in value for char in (":", "/", "\\", "@")):
        raise _invalid(field_name)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise _invalid(field_name)

    labels = value.split(".")
    if len(labels) < 2 or labels[-1] in _NON_PUBLIC_SUFFIXES:
        raise _invalid(field_name)
    for label in labels:
        if not label or len(label.encode("ascii")) > 63:
            raise _invalid(field_name)
        if _DOMAIN_LABEL_RE.fullmatch(label) is None:
            raise _invalid(field_name)
        if label.startswith("xn--"):
            try:
                decoded = idna.decode(
                    label.encode("ascii"),
                    uts46=False,
                    std3_rules=True,
                )
                canonical = idna.encode(
                    decoded,
                    uts46=False,
                    std3_rules=True,
                ).decode("ascii")
                if canonical.lower() != label:
                    raise _invalid(field_name)
            except (UnicodeError, ValueError, idna.IDNAError):
                raise _invalid(field_name) from None
    return value


def validate_rfc3339_utc(value: Any, field_name: str = "timestamp") -> str:
    """Require a calendar-valid RFC 3339 timestamp in canonical UTC ``Z`` form."""

    value = validate_nfc_string(
        value,
        field_name,
        minimum_utf8_bytes=20,
        maximum_utf8_bytes=30,
    )
    if _RFC3339_UTC_RE.fullmatch(value) is None:
        raise _invalid(field_name)
    try:
        # ``datetime.fromisoformat`` accepted a narrower set of fractional
        # second forms in early supported Python versions.  Validate the
        # calendar portion separately so 1..9 RFC 3339 fractional digits have
        # identical behavior on Python 3.8.1 and current Python.
        datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise _invalid(field_name) from None
    return value


def parse_rfc3339_utc(value: Any, field_name: str = "timestamp") -> datetime:
    value = validate_rfc3339_utc(value, field_name)
    parsed = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    if value[19] == ".":
        fraction = value[20:-1]
        parsed = parsed.replace(
            microsecond=int((fraction + "000000")[:6])
        )
    return parsed.replace(tzinfo=timezone.utc)


def validate_transaction_hash(value: Any) -> str:
    value = validate_nfc_string(
        value, "reward_tx_hash", minimum_utf8_bytes=66, maximum_utf8_bytes=66
    )
    if _TRANSACTION_HASH_RE.fullmatch(value) is None:
        raise _invalid("reward_tx_hash")
    return value


def validate_amount_atomic(value: Any) -> str:
    """Require a canonical positive integer encoded as a JSON string."""

    value = validate_nfc_string(
        value,
        "amount_atomic",
        minimum_utf8_bytes=1,
    )
    if _AMOUNT_ATOMIC_RE.fullmatch(value) is None:
        raise _invalid("amount_atomic")
    return value


def _validate_percent_encoded_path(path: str) -> None:
    if _PERCENT_ESCAPE_RE.search(path) is not None:
        raise _invalid("url")
    try:
        decoded = unquote_to_bytes(path).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise _invalid("url") from None
    validate_nfc_string(decoded, "url path")
    if "\\" in decoded:
        raise _invalid("url")


def validate_public_observation_url(
    value: Any,
    task_domain: Optional[str] = None,
    field_name: str = "url",
) -> str:
    """Validate a bounded public HTTP(S) URL, optionally bound to a domain."""

    value = validate_nfc_string(
        value,
        field_name,
        minimum_utf8_bytes=1,
        maximum_utf8_bytes=MAXIMUM_URL_UTF8_BYTES,
    )
    if "\\" in value or "?" in value or "#" in value:
        raise _invalid(field_name)
    if not (value.startswith("http://") or value.startswith("https://")):
        raise _invalid(field_name)

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise _invalid(field_name) from None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise _invalid(field_name)
    if parsed.username is not None or parsed.password is not None:
        raise _invalid(field_name)
    if parsed.query or parsed.fragment:
        raise _invalid(field_name)
    if port is not None and not (1 <= port <= 65535):
        raise _invalid(field_name)

    hostname = parsed.hostname
    if hostname is None:
        raise _invalid(field_name)
    # ``urlsplit().hostname`` lowercases, so inspect the original authority too
    # to reject a non-canonical uppercase host rather than silently changing it.
    raw_authority = parsed.netloc
    if port is not None:
        raw_host = raw_authority.rsplit(":", 1)[0]
    else:
        raw_host = raw_authority
    if raw_host != raw_host.lower() or raw_host != hostname:
        raise _invalid(field_name)

    validated_hostname = validate_public_domain(hostname, "url host")
    _validate_percent_encoded_path(parsed.path)

    if task_domain is not None:
        validated_domain = validate_public_domain(task_domain, "task domain")
        if (
            validated_hostname != validated_domain
            and not validated_hostname.endswith("." + validated_domain)
        ):
            raise _invalid(field_name)
    return value


def is_url_within_task_domain(value: Any, task_domain: Any) -> bool:
    try:
        validate_public_observation_url(value, task_domain=task_domain)
    except (TypeError, ValueError):
        return False
    return True


# Keccak-f[1600] constants.  A tiny dependency-free implementation is kept
# here because EIP-55 uses Keccak-256 (not hashlib.sha3_256), while the worker
# lane may not add a new mandatory dependency.
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_UINT64_MASK = (1 << 64) - 1


def _rotate_left_64(value: int, amount: int) -> int:
    if amount == 0:
        return value & _UINT64_MASK
    return (
        ((value << amount) | (value >> (64 - amount))) & _UINT64_MASK
    )


def _keccak_f1600(state: Sequence[int]) -> Tuple[int, ...]:
    lanes = list(state)
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        columns = [
            lanes[x]
            ^ lanes[x + 5]
            ^ lanes[x + 10]
            ^ lanes[x + 15]
            ^ lanes[x + 20]
            for x in range(5)
        ]
        differences = [
            columns[(x - 1) % 5]
            ^ _rotate_left_64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] ^= differences[x]

        permuted = [0] * 25
        for x in range(5):
            for y in range(5):
                destination_x = y
                destination_y = (2 * x + 3 * y) % 5
                permuted[destination_x + 5 * destination_y] = _rotate_left_64(
                    lanes[x + 5 * y], _KECCAK_ROTATIONS[x][y]
                )

        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] = (
                    permuted[x + 5 * y]
                    ^ (
                        (~permuted[((x + 1) % 5) + 5 * y])
                        & permuted[((x + 2) % 5) + 5 * y]
                    )
                ) & _UINT64_MASK
        lanes[0] ^= round_constant
    return tuple(lanes)


def _keccak_256(data: bytes) -> bytes:
    rate_bytes = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate_bytes != rate_bytes - 1:
        padded.append(0x00)
    padded.append(0x80)

    state = (0,) * 25
    for offset in range(0, len(padded), rate_bytes):
        block = padded[offset : offset + rate_bytes]
        mutable_state = list(state)
        for lane_index in range(rate_bytes // 8):
            lane = int.from_bytes(
                block[lane_index * 8 : lane_index * 8 + 8], "little"
            )
            mutable_state[lane_index] ^= lane
        state = _keccak_f1600(mutable_state)

    output = bytearray()
    while len(output) < 32:
        for lane_index in range(rate_bytes // 8):
            output.extend(int(state[lane_index]).to_bytes(8, "little"))
            if len(output) >= 32:
                return bytes(output[:32])
        state = _keccak_f1600(state)
    return bytes(output[:32])


def to_eip55_checksum_address(address: Any) -> str:
    """Validate and canonicalize a non-zero 20-byte EVM address."""

    address = validate_nfc_string(
        address,
        "reward_address",
        minimum_utf8_bytes=42,
        maximum_utf8_bytes=42,
    )
    if _EVM_ADDRESS_RE.fullmatch(address) is None:
        raise _invalid("reward_address")
    hexadecimal = address[2:]
    if int(hexadecimal, 16) == 0:
        raise _invalid("reward_address")

    lower = hexadecimal.lower()
    digest_hex = _keccak_256(lower.encode("ascii")).hex()
    checksummed = "".join(
        char.upper()
        if char in "abcdef" and int(digest_hex[index], 16) >= 8
        else char
        for index, char in enumerate(lower)
    )
    canonical = "0x" + checksummed

    has_lower = any(char in "abcdef" for char in hexadecimal)
    has_upper = any(char in "ABCDEF" for char in hexadecimal)
    if has_lower and has_upper and address != canonical:
        raise _invalid("reward_address")
    return canonical


def validate_reward_address(address: Any) -> str:
    return to_eip55_checksum_address(address)


def validate_claim_token(value: Any) -> str:
    """Require the canonical 32-byte, unpadded base64url claim capability."""

    value = validate_nfc_string(
        value,
        "claim_token",
        minimum_utf8_bytes=CLAIM_TOKEN_ENCODED_LENGTH,
        maximum_utf8_bytes=CLAIM_TOKEN_ENCODED_LENGTH,
    )
    if _CLAIM_TOKEN_RE.fullmatch(value) is None:
        raise _invalid("claim_token")
    try:
        decoded = base64.urlsafe_b64decode((value + "=").encode("ascii"))
    except (ValueError, UnicodeError):
        raise _invalid("claim_token") from None
    if len(decoded) != CLAIM_TOKEN_BYTE_LENGTH:
        raise _invalid("claim_token")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise _invalid("claim_token")
    return value


def decode_claim_token(value: Any) -> bytes:
    value = validate_claim_token(value)
    return base64.urlsafe_b64decode((value + "=").encode("ascii"))


def claim_token_storage_digest(value: Any) -> bytes:
    """Return the fixed domain-separated digest used by Hon-den storage."""

    token_bytes = decode_claim_token(value)
    return hashlib.sha256(CLAIM_TOKEN_DOMAIN_SEPARATOR + token_bytes).digest()


def claim_token_storage_digest_hex(value: Any) -> str:
    return claim_token_storage_digest(value).hex()


def validate_fixed_api_origin(value: Any) -> str:
    value = validate_nfc_string(value, "api_origin")
    if value != PUBLIC_API_ORIGIN:
        raise _invalid("api_origin")
    return value


def _task_id_path_segment(task_id: Any) -> str:
    """Keep opaque dot-segment IDs inside the fixed Task route.

    RFC 3986 treats ``.`` and ``..`` specially during URL resolution.  The
    wire identifier grammar permits those opaque values, so encode only those
    two complete segments before handing the path to an HTTP URL parser.
    """

    canonical = validate_task_id(task_id)
    if canonical == ".":
        return "%2E"
    if canonical == "..":
        return "%2E%2E"
    return canonical


def task_detail_path(task_id: Any) -> str:
    return TASK_DETAIL_PATH_TEMPLATE.format(
        task_id=_task_id_path_segment(task_id)
    )


def task_submission_status_path(task_id: Any, submission_id: Any) -> str:
    return TASK_SUBMISSION_STATUS_PATH_TEMPLATE.format(
        task_id=_task_id_path_segment(task_id),
        submission_id=validate_submission_id(submission_id),
    )


def task_claim_path(task_id: Any) -> str:
    return TASK_CLAIM_PATH_TEMPLATE.format(
        task_id=_task_id_path_segment(task_id)
    )


def task_observation_path(task_id: Any) -> str:
    return TASK_OBSERVATION_PATH_TEMPLATE.format(
        task_id=_task_id_path_segment(task_id)
    )


def task_completion_path(task_id: Any) -> str:
    return TASK_COMPLETION_PATH_TEMPLATE.format(
        task_id=_task_id_path_segment(task_id)
    )


def _jcs_string(value: str) -> str:
    validate_nfc_string(value, "canonical JSON string")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _jcs_text(value: Any) -> str:
    """Serialize the integer-only v1 schema as RFC 8785-compatible JSON."""

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        # All v1 schema numbers are much smaller.  Keeping this I-JSON bound
        # prevents a generic caller from relying on non-interoperable integers.
        if abs(value) > 9007199254740991:
            raise ValueError("Canonical JSON integer is outside the safe range.")
        return str(value)
    if isinstance(value, float):
        raise ValueError("Canonical Task JSON does not accept floating-point values.")
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_text(item) for item in value) + "]"
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if not all(isinstance(key, str) for key in keys):
            raise ValueError("Canonical JSON object keys must be strings.")
        for key in keys:
            validate_nfc_string(key, "canonical JSON object key")
        keys.sort(key=lambda key: key.encode("utf-16be"))
        return "{" + ",".join(
            _jcs_string(key) + ":" + _jcs_text(value[key]) for key in keys
        ) + "}"
    raise ValueError("Unsupported value in canonical Task JSON.")


def jcs_canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785-compatible UTF-8 bytes for the fixed integer schema."""

    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return _jcs_text(value).encode("utf-8")


def canonical_submission_bytes(value: Any) -> bytes:
    return jcs_canonical_bytes(value)


def canonical_submission_digest(value: Any) -> bytes:
    return hashlib.sha256(canonical_submission_bytes(value)).digest()


def canonical_submission_digest_hex(value: Any) -> str:
    return canonical_submission_digest(value).hex()


# Readable aliases for callers and tests.
compute_submission_digest = canonical_submission_digest_hex
submission_digest_hex = canonical_submission_digest_hex


def reward_state_for_task_status(task_status: Any) -> str:
    if not isinstance(task_status, str):
        raise _invalid("task_status")
    try:
        return REWARD_STATE_BY_TASK_STATUS[task_status]
    except KeyError:
        raise _invalid("task_status") from None


def failure_codes_for_task_status(task_status: Any) -> frozenset:
    """Return the exact public-safe failure-code scope for one Submission."""

    if not isinstance(task_status, str):
        raise _invalid("task_status")
    try:
        return FAILURE_CODES_BY_TASK_STATUS[task_status]
    except KeyError:
        raise _invalid("task_status") from None


__all__ = [
    "AGENT_ID_PATTERN",
    "CLAIM_MAXIMUM_ATTEMPTS",
    "CLAIM_LEASE_DURATION_SECONDS",
    "CLAIM_REQUEST_SCHEMA_VERSION",
    "CLAIM_RESPONSE_SCHEMA_VERSION",
    "CLAIM_RESPONSE_STATUSES",
    "CLAIM_TOKEN_HEADER",
    "COMPLETION_MAXIMUM_ATTEMPTS",
    "COMPLETION_REQUEST_SCHEMA_VERSION",
    "COMPLETION_RESPONSE_SCHEMA_VERSION",
    "CONNECT_TIMEOUT_SECONDS",
    "CONTRACT_ID",
    "CREDENTIAL_FILE_SCHEMA_VERSION",
    "DEFAULT_TASK_LIST_LIMIT",
    "DEFAULT_TASK_DETAIL_LIMIT",
    "EVALUATION_REJECTION_FAILURE_CODES",
    "ERROR_SCHEMA_VERSION",
    "LIST_DETAIL_BACKOFF_SECONDS",
    "LIST_DETAIL_MAXIMUM_ATTEMPTS",
    "FAILURE_CODES_BY_TASK_STATUS",
    "LOCAL_AMBIGUOUS_DELIVERY_CODES",
    "LOCAL_ERROR_CODES",
    "MAXIMUM_DISCOVERED_SURFACES",
    "MAXIMUM_CURSOR_UTF8_BYTES",
    "MAXIMUM_JSON_BYTES",
    "MAXIMUM_OBSERVATION_ERRORS",
    "MAXIMUM_OBSERVED_URLS",
    "MAXIMUM_TASK_LIST_LIMIT",
    "MAXIMUM_TASK_DETAIL_LIMIT",
    "MAXIMUM_URL_UTF8_BYTES",
    "MINIMUM_TASK_LIST_LIMIT",
    "MINIMUM_TASK_DETAIL_LIMIT",
    "MUTATION_FREE_CLAIM_ERROR_CODES_BY_STATUS",
    "OBSERVATION_ID_PATTERN",
    "OBSERVATION_MAXIMUM_ATTEMPTS",
    "OBSERVATION_RESPONSE_SCHEMA_VERSION",
    "OBSERVATION_SUBMISSION_SCHEMA_VERSION",
    "POOL_TIMEOUT_SECONDS",
    "PUBLIC_API_ORIGIN",
    "PUBLIC_ERROR_CODES",
    "PUBLIC_ERROR_CODES_BY_STATUS",
    "PUBLIC_SUBMISSION_FAILURE_CODES",
    "PUBLIC_SUBMISSION_STATUSES",
    "PRIVATE_EXECUTION_STATUSES",
    "READ_TIMEOUT_SECONDS",
    "REWARD_ASSET",
    "REWARD_ASSET_ADDRESS",
    "REWARD_NETWORK",
    "REWARD_AMBIGUOUS_FAILURE_CODES",
    "REWARD_FAILURE_CODES",
    "REWARD_POLL_DEFAULT_TIMEOUT_SECONDS",
    "REWARD_POLL_INITIAL_BACKOFF_SECONDS",
    "REWARD_POLL_MAXIMUM_ATTEMPTS",
    "REWARD_POLL_MAXIMUM_BACKOFF_SECONDS",
    "REWARD_POLL_MAXIMUM_JITTER_SECONDS",
    "REWARD_POLL_MAXIMUM_RETRY_AFTER_SECONDS",
    "REWARD_STATE_BY_TASK_STATUS",
    "REWARD_STATUS_SCHEMA_VERSION",
    "RETRYABLE_HTTP_STATUSES",
    "SUBMISSION_ID_PATTERN",
    "TASK_CLAIM_PATH_TEMPLATE",
    "TASK_COMPLETION_PATH_TEMPLATE",
    "TASK_DETAIL_PATH_TEMPLATE",
    "TASK_LIST_PATH",
    "TASK_OBSERVATION_PATH_TEMPLATE",
    "TASK_PAGE_SCHEMA_VERSION",
    "TASK_SCHEMA_VERSION",
    "TASK_SUBMISSION_STATUS_PATH_TEMPLATE",
    "TASK_STATUSES",
    "TASK_OFFER_STATUSES",
    "TASK_TYPE_PAYMENT_SURFACE_DISCOVERY",
    "TOTAL_OPERATION_TIMEOUT_SECONDS",
    "WRITE_TIMEOUT_SECONDS",
    "canonical_submission_bytes",
    "canonical_submission_digest",
    "canonical_submission_digest_hex",
    "claim_token_storage_digest",
    "claim_token_storage_digest_hex",
    "compute_submission_digest",
    "decode_claim_token",
    "failure_codes_for_task_status",
    "generate_submission_id",
    "is_url_within_task_domain",
    "jcs_canonical_bytes",
    "parse_rfc3339_utc",
    "reward_state_for_task_status",
    "submission_digest_hex",
    "task_claim_path",
    "task_completion_path",
    "task_detail_path",
    "task_observation_path",
    "task_submission_status_path",
    "to_eip55_checksum_address",
    "validate_agent_id",
    "validate_amount_atomic",
    "validate_claim_token",
    "validate_cursor",
    "validate_fixed_api_origin",
    "validate_manifest_sha256",
    "validate_manifest_url",
    "validate_nfc_string",
    "validate_observation_id",
    "validate_public_domain",
    "validate_public_observation_url",
    "validate_reward_address",
    "validate_rfc3339_utc",
    "validate_submission_id",
    "validate_task_definition_digest",
    "validate_task_definition_version",
    "validate_task_id",
    "validate_transaction_hash",
]
