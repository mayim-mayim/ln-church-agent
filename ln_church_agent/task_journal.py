"""Durable fail-closed journal for v1.18 scheduled Task execution.

The journal is keyed by ``(task_id, local_claim_credential_handle)`` and is
also bound to one execution identifier.  Secret credentials and signed
Manifest URLs are never accepted.  Every update is protected by a stable
sibling lock and uses a same-directory, flushed atomic replacement.  A write
whose durability is uncertain is reported as terminally ambiguous; callers
must not continue target I/O after such an error.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

from .task_contract import jcs_canonical_bytes, validate_task_id


JOURNAL_SCHEMA_VERSION = "ln_church.scheduled_http_get_batch_journal.v1"
JOURNAL_CHECKSUM_DOMAIN = b"ln_church.scheduled_http_get_batch_journal.v1\x00"
JOURNAL_MAXIMUM_BYTES = 256 * 1024

_EXECUTION_ID_DOMAIN = b"ln_church.scheduled_http_get_batch.execution.v1\x00"
_TASK_TYPE = "scheduled_http_get_batch.v1"
_TASK_DEFINITION_VERSION = "1.0.0"

_HANDLE_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_EXECUTION_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SUBMISSION_RE = re.compile(r"^sub_[a-f0-9]{32}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$"
)
_SECRET_KEY_RE = re.compile(
    r"(?:claim[_-]?token|signed[_-]?(?:url|manifest)|authorization|cookie|secret)",
    re.IGNORECASE,
)
_TOKEN_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

_FROZEN_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "submission_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_sha256",
        "manifest_fetch",
        "results",
        "completed_at",
    }
)
_COMPOUND_ACK_COMMON_KEYS = frozenset(
    {
        "source",
        "task_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_sha256",
        "submission_id",
        "report_id",
        "report_sha256",
        "accepted_at",
        "receipt_state",
    }
)
_COMPOUND_RECEIPT_ACK_KEYS = frozenset(
    set(_COMPOUND_ACK_COMMON_KEYS) | {"completion_id"}
)
_RECEIPT_SOURCE_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_sha256",
        "submission_id",
        "report_id",
        "report_sha256",
        "completion_id",
        "accepted_at",
        "receipt_state",
        "evaluation_state",
    }
)
_STATUS_SOURCE_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_sha256",
        "submission_id",
        "report_id",
        "report_sha256",
        "accepted_at",
        "receipt_state",
        "evaluation",
        "base_reward",
        "reference_bonus",
        "terminal",
        "retry_after_seconds",
    }
)

_STATES = frozenset(
    {
        "INIT",
        "OFFER_RECHECKED",
        "MANIFEST_FETCH_STARTED",
        "MANIFEST_VERIFIED",
        "ATTEMPT_STARTED",
        "RESULT_RECORDED",
        "REPORT_FROZEN",
        "COMPOUND_COMPLETION_ACKED",
        "TERMINAL_STATUS",
    }
)
_TARGET_STATES = frozenset({"UNSTARTED", "ATTEMPT_STARTED", "RESULT_RECORDED"})
_TARGET_OUTCOMES = frozenset(
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
_MANIFEST_OUTCOMES = frozenset(
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


class JournalError(Exception):
    """Finite, path-free journal failure."""

    def __init__(self, code: str) -> None:
        if code not in {
            "JOURNAL_INVALID",
            "JOURNAL_MISSING",
            "JOURNAL_LOCKED",
            "JOURNAL_PERSISTENCE_AMBIGUOUS",
            "JOURNAL_STATE_CONFLICT",
        }:
            code = "JOURNAL_INVALID"
        super().__init__(code)
        self.code = code


class JournalPersistenceError(JournalError):
    def __init__(self) -> None:
        super().__init__("JOURNAL_PERSISTENCE_AMBIGUOUS")


@dataclass(frozen=True)
class JournalSnapshot:
    payload: Mapping[str, Any]

    @property
    def state(self) -> str:
        return str(self.payload["state"])

    @property
    def sequence(self) -> int:
        return int(self.payload["sequence"])


def _validated_identifier(value: Any, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise JournalError("JOURNAL_INVALID")
    return value


def _validated_definition_identity(
    task_type: Any,
    task_definition_version: Any,
    task_definition_digest: Any,
) -> Tuple[str, str, str]:
    if (
        type(task_type) is not str
        or task_type != _TASK_TYPE
        or type(task_definition_version) is not str
        or task_definition_version != _TASK_DEFINITION_VERSION
        or type(task_definition_digest) is not str
        or _SHA256_RE.fullmatch(task_definition_digest) is None
    ):
        raise JournalError("JOURNAL_INVALID")
    return task_type, task_definition_version, task_definition_digest


def derive_local_execution_id(
    task_id: Any, local_claim_credential_handle: Any
) -> str:
    """Derive the only valid private execution identifier for a journal key."""

    try:
        task = validate_task_id(task_id)
    except Exception:
        raise JournalError("JOURNAL_INVALID") from None
    handle = _validated_identifier(local_claim_credential_handle, _HANDLE_RE)
    digest = hashlib.sha256(
        _EXECUTION_ID_DOMAIN
        + task.encode("ascii")
        + b"\x00"
        + handle.encode("ascii")
    ).hexdigest()
    return "exec_" + digest[:32]


def _validate_journal_path(path: Any) -> Path:
    if not isinstance(path, (str, os.PathLike)) or not str(path):
        raise JournalError("JOURNAL_INVALID")
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent = absolute.parent
    if not parent.exists() or not parent.is_dir():
        raise JournalError("JOURNAL_INVALID")
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise JournalError("JOURNAL_INVALID")
        allowed = Path(os.path.abspath(local)) / "ln-church-agent" / "claims"
        try:
            common = os.path.commonpath(
                [os.path.normcase(str(absolute)), os.path.normcase(str(allowed))]
            )
        except ValueError:
            raise JournalError("JOURNAL_INVALID") from None
        if common != os.path.normcase(str(allowed)):
            raise JournalError("JOURNAL_INVALID")
        # ``lstat`` detects ordinary symlink/reparse-path substitutions in the
        # supported pathlib surface; native qualification covers Windows
        # sharing and reparse behavior separately.
        current = Path(parent.anchor)
        for part in parent.parts[1:]:
            current = current / part
            info = os.lstat(str(current))
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise JournalError("JOURNAL_INVALID")
        return absolute
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current = current / part
        info = os.lstat(str(current))
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise JournalError("JOURNAL_INVALID")
    parent_info = os.lstat(str(parent))
    if parent_info.st_mode & 0o022 and not parent_info.st_mode & stat.S_ISVTX:
        raise JournalError("JOURNAL_INVALID")
    if (
        hasattr(os, "geteuid")
        and parent_info.st_uid != os.geteuid()
        and not parent_info.st_mode & stat.S_ISVTX
    ):
        raise JournalError("JOURNAL_INVALID")
    return absolute


def _reject_duplicate_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ValueError


def _contains_secret(value: Any, *, key: Optional[str] = None) -> bool:
    if key is not None and _SECRET_KEY_RE.search(key):
        return True
    if isinstance(value, Mapping):
        return any(
            type(item_key) is not str
            or _contains_secret(item, key=item_key)
            for item_key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_secret(item) for item in value)
    if type(value) is str:
        lowered = value.lower()
        return (
            _TOKEN_VALUE_RE.fullmatch(value) is not None
            or "x-ln-task-claim-token" in lowered
            or "cloudfront-key-pair-id" in lowered
            or "cloudfront-signature" in lowered
            or "cloudfront-policy" in lowered
        )
    return False


def _decoded_frozen_report(
    payload: Mapping[str, Any], report_bytes: bytes
) -> Dict[str, Any]:
    try:
        report = json.loads(
            report_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise JournalError("JOURNAL_INVALID") from None
    if type(report) is not dict or set(report) != _FROZEN_REPORT_KEYS:
        raise JournalError("JOURNAL_INVALID")
    if (
        report["schema_version"]
        != "ln_church.scheduled_http_get_batch_completion.v1"
        or report["submission_id"] != payload["submission_id"]
        or report["task_type"] != payload["task_type"]
        or report["task_definition_version"]
        != payload["task_definition_version"]
        or report["task_definition_digest"]
        != payload["task_definition_digest"]
        or type(report["manifest_sha256"]) is not str
        or _SHA256_RE.fullmatch(report["manifest_sha256"]) is None
        or type(report["completed_at"]) is not str
        or _RFC3339_RE.fullmatch(report["completed_at"]) is None
        or type(report["manifest_fetch"]) is not dict
        or report["manifest_fetch"].get("outcome")
        != payload["manifest_fetch_outcome"]
        or type(report["results"]) is not list
    ):
        raise JournalError("JOURNAL_INVALID")
    if (
        payload["manifest_sha256"] is None
        or report["manifest_sha256"] != payload["manifest_sha256"]
    ):
        raise JournalError("JOURNAL_INVALID")
    manifest_fetch = report["manifest_fetch"]
    fetch_outcome = manifest_fetch.get("outcome")
    if fetch_outcome not in _MANIFEST_OUTCOMES:
        raise JournalError("JOURNAL_INVALID")
    required_fetch_fields = {"outcome"}
    if fetch_outcome in {"retrieved", "release_digest_mismatch"}:
        required_fetch_fields.update({"http_status", "observed_sha256"})
    elif fetch_outcome == "release_http_unexpected_status":
        required_fetch_fields.add("http_status")
    if not required_fetch_fields.issubset(manifest_fetch) or not set(
        manifest_fetch
    ).issubset(required_fetch_fields | {"elapsed_ms"}):
        raise JournalError("JOURNAL_INVALID")
    observed = manifest_fetch.get("observed_sha256")
    fetch_status = manifest_fetch.get("http_status")
    fetch_elapsed = manifest_fetch.get("elapsed_ms")
    if "elapsed_ms" in manifest_fetch and (
        type(fetch_elapsed) is not int or not 0 <= fetch_elapsed <= 5000
    ):
        raise JournalError("JOURNAL_INVALID")
    if fetch_outcome == "retrieved":
        fetch_fields_valid = (
            fetch_status == 200 and observed == report["manifest_sha256"]
        )
    elif fetch_outcome == "release_http_unexpected_status":
        fetch_fields_valid = (
            type(fetch_status) is int
            and 201 <= fetch_status <= 599
            and observed is None
        )
    elif fetch_outcome == "release_digest_mismatch":
        fetch_fields_valid = (
            fetch_status == 200
            and type(observed) is str
            and _SHA256_RE.fullmatch(observed) is not None
            and observed != report["manifest_sha256"]
        )
    else:
        fetch_fields_valid = fetch_status is None and observed is None
    if not fetch_fields_valid:
        raise JournalError("JOURNAL_INVALID")
    for position, result in enumerate(report["results"]):
        result_outcome = result.get("outcome") if type(result) is dict else None
        required_result_fields = {"position", "target_url", "outcome"}
        if result_outcome == "http_response":
            required_result_fields.add("http_status")
        if (
            type(result) is not dict
            or not required_result_fields.issubset(result)
            or not set(result).issubset(
                required_result_fields | {"elapsed_ms"}
            )
            or result["position"] != position
            or type(result["target_url"]) is not str
            or not result["target_url"].startswith("https://")
            or result_outcome not in _TARGET_OUTCOMES
            or (
                "elapsed_ms" in result
                and (
                    type(result.get("elapsed_ms")) is not int
                    or not 0 <= result["elapsed_ms"] <= 12000
                )
            )
            or (
                result_outcome == "http_response"
                and (
                    type(result.get("http_status")) is not int
                    or not 200 <= result["http_status"] <= 599
                )
            )
            or (
                result_outcome != "http_response"
                and "http_status" in result
            )
        ):
            raise JournalError("JOURNAL_INVALID")
    try:
        if jcs_canonical_bytes(report) != report_bytes:
            raise JournalError("JOURNAL_INVALID")
    except JournalError:
        raise
    except Exception:
        raise JournalError("JOURNAL_INVALID") from None
    if fetch_outcome == "retrieved":
        if (
            payload["manifest_bytes_b64"] is None
            or payload["target_count"] is None
            or len(report["results"]) != payload["target_count"]
        ):
            raise JournalError("JOURNAL_INVALID")
        for position, (result, target) in enumerate(
            zip(report["results"], payload["targets"])
        ):
            if (
                type(result) is not dict
                or result.get("position") != position
                or target.get("state") != "RESULT_RECORDED"
                or result.get("outcome") != target.get("outcome")
                or result.get("http_status") != target.get("http_status")
                or result.get("elapsed_ms") != target.get("elapsed_ms")
            ):
                raise JournalError("JOURNAL_INVALID")
    elif report["results"] or payload["targets"]:
        raise JournalError("JOURNAL_INVALID")
    return report


def _normalise_acknowledgement(value: Any) -> Dict[str, str]:
    if hasattr(value, "model_dump"):
        try:
            value = value.model_dump(mode="python", exclude_none=True)
        except Exception:
            raise JournalError("JOURNAL_INVALID") from None
    if type(value) is not dict:
        if isinstance(value, Mapping):
            value = dict(value)
        else:
            raise JournalError("JOURNAL_INVALID")
    source = value.get("source")
    expected_keys = (
        _COMPOUND_RECEIPT_ACK_KEYS
        if source == "receipt"
        else _COMPOUND_ACK_COMMON_KEYS
    )
    if source in {"receipt", "status"} and set(value) == expected_keys:
        facts = dict(value)
    else:
        if set(value) - {"source", "receipt", "status"} or "source" not in value:
            raise JournalError("JOURNAL_INVALID")
        source = value["source"]
        selected_key = "receipt" if source == "receipt" else "status"
        other_key = "status" if source == "receipt" else "receipt"
        if source not in {"receipt", "status"} or value.get(other_key) is not None:
            raise JournalError("JOURNAL_INVALID")
        selected = value.get(selected_key)
        if hasattr(selected, "model_dump"):
            try:
                selected = selected.model_dump(mode="python", exclude_none=True)
            except Exception:
                raise JournalError("JOURNAL_INVALID") from None
        if type(selected) is not dict:
            raise JournalError("JOURNAL_INVALID")
        selected_keys = (
            _RECEIPT_SOURCE_KEYS if source == "receipt" else _STATUS_SOURCE_KEYS
        )
        if set(selected) != selected_keys:
            raise JournalError("JOURNAL_INVALID")
        if source == "receipt":
            if (
                selected["schema_version"]
                != "ln_church.agent_task_completion_receipt.v2"
                or selected["evaluation_state"]
                not in {"PENDING", "APPROVED", "REJECTED", "BLOCKED"}
            ):
                raise JournalError("JOURNAL_INVALID")
        else:
            evaluation = selected["evaluation"]
            base_reward = selected["base_reward"]
            reference_bonus = selected["reference_bonus"]
            retry_after = selected["retry_after_seconds"]
            settlement_states = {
                "NOT_CREATED",
                "DUE",
                "SUBMITTING",
                "CONFIRMING",
                "PAID_CONFIRMED",
                "RETRYABLE_KNOWN_FAILURE",
                "AMBIGUOUS",
                "FAILED",
            }
            evaluation_keys = (
                set(evaluation) if type(evaluation) is dict else set()
            )
            reference_keys = (
                set(reference_bonus)
                if type(reference_bonus) is dict
                else set()
            )
            reason = (
                evaluation.get("reason")
                if type(evaluation) is dict
                else None
            )
            reference_decision = (
                reference_bonus.get("decision_state")
                if type(reference_bonus) is dict
                else None
            )
            if (
                selected["schema_version"]
                != "ln_church.agent_task_reward_status.v2"
                or type(evaluation) is not dict
                or evaluation_keys not in ({"state"}, {"state", "reason"})
                or evaluation["state"]
                not in {"PENDING", "APPROVED", "REJECTED", "BLOCKED"}
                or (
                    "reason" in evaluation
                    and (
                        type(reason) is not str
                        or not 1 <= len(reason) <= 128
                    )
                )
                or type(base_reward) is not dict
                or set(base_reward) != {"entitlement_state", "settlement_state"}
                or base_reward["entitlement_state"]
                not in {"NOT_CREATED", "DUE", "TERMINAL"}
                or base_reward["settlement_state"] not in settlement_states
                or type(reference_bonus) is not dict
                or reference_keys
                not in (
                    {"candidate", "decision_state"},
                    {"candidate", "decision_state", "settlement_state"},
                )
                or type(reference_bonus["candidate"]) is not bool
                or reference_decision
                not in {"PENDING", "AWARDED", "NOT_AWARDED", "FAILED"}
                or (
                    reference_decision == "AWARDED"
                    and (
                        "settlement_state" not in reference_bonus
                        or reference_bonus["settlement_state"]
                        not in settlement_states
                    )
                )
                or (
                    reference_decision != "AWARDED"
                    and "settlement_state" in reference_bonus
                )
                or type(selected["terminal"]) is not bool
                or type(retry_after) is not int
                or not 0 <= retry_after <= 3600
                or (selected["terminal"] and retry_after != 0)
                or (not selected["terminal"] and retry_after < 1)
            ):
                raise JournalError("JOURNAL_INVALID")
        expected_keys = (
            _COMPOUND_RECEIPT_ACK_KEYS
            if source == "receipt"
            else _COMPOUND_ACK_COMMON_KEYS
        )
        facts = {"source": source}
        for key in expected_keys - {"source"}:
            if key not in selected:
                raise JournalError("JOURNAL_INVALID")
            facts[key] = selected[key]
    if set(facts) != expected_keys or any(
        type(item) is not str for item in facts.values()
    ):
        raise JournalError("JOURNAL_INVALID")
    return facts


def _validate_compound_ack(
    payload: Mapping[str, Any], value: Any
) -> Dict[str, str]:
    facts = _normalise_acknowledgement(value)
    if (
        facts["source"] not in {"receipt", "status"}
        or facts["task_id"] != payload["task_id"]
        or facts["task_type"] != payload["task_type"]
        or facts["task_definition_version"]
        != payload["task_definition_version"]
        or facts["task_definition_digest"]
        != payload["task_definition_digest"]
        or _SHA256_RE.fullmatch(facts["manifest_sha256"]) is None
        or facts["submission_id"] != payload["submission_id"]
        or _SUBMISSION_RE.fullmatch(facts["submission_id"]) is None
        or _EXECUTION_RE.fullmatch(facts["report_id"]) is None
        or (
            facts["source"] == "receipt"
            and _EXECUTION_RE.fullmatch(facts["completion_id"]) is None
        )
        or facts["report_sha256"] != payload["frozen_report_sha256"]
        or _SHA256_RE.fullmatch(facts["report_sha256"]) is None
        or _RFC3339_RE.fullmatch(facts["accepted_at"]) is None
        or facts["receipt_state"] != "DURABLY_ACCEPTED"
    ):
        raise JournalError("JOURNAL_INVALID")
    report_b64 = payload["frozen_report_bytes_b64"]
    if type(report_b64) is not str:
        raise JournalError("JOURNAL_INVALID")
    try:
        report_bytes = base64.b64decode(report_b64, validate=True)
    except (ValueError, TypeError):
        raise JournalError("JOURNAL_INVALID") from None
    report = _decoded_frozen_report(payload, report_bytes)
    if (
        facts["task_type"] != report["task_type"]
        or facts["task_definition_version"]
        != report["task_definition_version"]
        or facts["task_definition_digest"] != report["task_definition_digest"]
        or facts["manifest_sha256"] != report["manifest_sha256"]
        or facts["submission_id"] != report["submission_id"]
    ):
        raise JournalError("JOURNAL_INVALID")
    return facts


def _normalise_terminal_status(value: Any) -> Dict[str, Any]:
    if hasattr(value, "model_dump"):
        try:
            value = value.model_dump(mode="python", exclude_none=True)
        except Exception:
            raise JournalError("JOURNAL_INVALID") from None
    if type(value) is not dict or set(value) != _STATUS_SOURCE_KEYS:
        raise JournalError("JOURNAL_INVALID")
    # Reuse the canonical status-shape validator; terminality itself is a
    # separate irreversible fact and may never be inferred from evaluation.
    _normalise_acknowledgement({"source": "status", "status": value})
    if value["terminal"] is not True:
        raise JournalError("JOURNAL_INVALID")
    return dict(value)


def _validate_terminal_status(
    payload: Mapping[str, Any], value: Any
) -> Dict[str, Any]:
    status = _normalise_terminal_status(value)
    status_facts = _validate_compound_ack(
        payload, {"source": "status", "status": status}
    )
    ack_facts = _validate_compound_ack(payload, payload["compound_ack"])
    for key in _COMPOUND_ACK_COMMON_KEYS - {"source"}:
        if status_facts[key] != ack_facts[key]:
            raise JournalError("JOURNAL_INVALID")
    return status


def _checksum(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        JOURNAL_CHECKSUM_DOMAIN + jcs_canonical_bytes(payload)
    ).hexdigest()


def _new_payload(
    task_id: str,
    handle: str,
    execution_id: str,
    task_type: str,
    task_definition_version: str,
    task_definition_digest: str,
) -> Dict[str, Any]:
    return {
        "task_id": task_id,
        "local_claim_credential_handle": handle,
        "execution_id": execution_id,
        "task_type": task_type,
        "task_definition_version": task_definition_version,
        "task_definition_digest": task_definition_digest,
        "state": "INIT",
        "sequence": 0,
        "manifest_sha256": None,
        "manifest_bytes_b64": None,
        "manifest_attempts_started": 0,
        "manifest_fetch_outcome": None,
        "target_count": None,
        "targets": [],
        "submission_id": None,
        "frozen_report_sha256": None,
        "frozen_report_bytes_b64": None,
        "completion_dispatch_attempts": 0,
        "compound_ack": None,
        "terminal_status": None,
    }


def _validate_payload(payload: Any) -> Dict[str, Any]:
    if type(payload) is not dict or set(payload) != {
        "task_id",
        "local_claim_credential_handle",
        "execution_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "state",
        "sequence",
        "manifest_sha256",
        "manifest_bytes_b64",
        "manifest_attempts_started",
        "manifest_fetch_outcome",
        "target_count",
        "targets",
        "submission_id",
        "frozen_report_sha256",
        "frozen_report_bytes_b64",
        "completion_dispatch_attempts",
        "compound_ack",
        "terminal_status",
    }:
        raise JournalError("JOURNAL_INVALID")
    try:
        validate_task_id(payload["task_id"])
    except Exception:
        raise JournalError("JOURNAL_INVALID") from None
    _validated_identifier(payload["local_claim_credential_handle"], _HANDLE_RE)
    _validated_identifier(payload["execution_id"], _EXECUTION_RE)
    if payload["execution_id"] != derive_local_execution_id(
        payload["task_id"], payload["local_claim_credential_handle"]
    ):
        raise JournalError("JOURNAL_INVALID")
    _validated_definition_identity(
        payload["task_type"],
        payload["task_definition_version"],
        payload["task_definition_digest"],
    )
    if payload["state"] not in _STATES:
        raise JournalError("JOURNAL_INVALID")
    if type(payload["sequence"]) is not int or payload["sequence"] < 0:
        raise JournalError("JOURNAL_INVALID")
    if (
        type(payload["manifest_attempts_started"]) is not int
        or not 0 <= payload["manifest_attempts_started"] <= 3
    ):
        raise JournalError("JOURNAL_INVALID")
    digest = payload["manifest_sha256"]
    if digest is not None and (
        type(digest) is not str or _SHA256_RE.fullmatch(digest) is None
    ):
        raise JournalError("JOURNAL_INVALID")
    manifest_b64 = payload["manifest_bytes_b64"]
    if manifest_b64 is not None:
        if type(manifest_b64) is not str or digest is None:
            raise JournalError("JOURNAL_INVALID")
        try:
            manifest_bytes = base64.b64decode(manifest_b64, validate=True)
        except (ValueError, TypeError):
            raise JournalError("JOURNAL_INVALID") from None
        if (
            not manifest_bytes
            or len(manifest_bytes) > 32768
            or hashlib.sha256(manifest_bytes).hexdigest() != digest
        ):
            raise JournalError("JOURNAL_INVALID")
    outcome = payload["manifest_fetch_outcome"]
    if outcome is not None and outcome not in _MANIFEST_OUTCOMES:
        raise JournalError("JOURNAL_INVALID")
    target_count = payload["target_count"]
    if target_count is not None and (
        type(target_count) is not int or not 0 <= target_count <= 10
    ):
        raise JournalError("JOURNAL_INVALID")
    targets = payload["targets"]
    if type(targets) is not list or (target_count is not None and len(targets) != target_count):
        raise JournalError("JOURNAL_INVALID")
    for position, target in enumerate(targets):
        if type(target) is not dict or set(target) - {
            "position",
            "state",
            "outcome",
            "http_status",
            "elapsed_ms",
        }:
            raise JournalError("JOURNAL_INVALID")
        if target.get("position") != position or target.get("state") not in _TARGET_STATES:
            raise JournalError("JOURNAL_INVALID")
        if target["state"] in {"UNSTARTED", "ATTEMPT_STARTED"}:
            if set(target) != {"position", "state"}:
                raise JournalError("JOURNAL_INVALID")
        elif not {"position", "state", "outcome"}.issubset(target):
            raise JournalError("JOURNAL_INVALID")
        item_outcome = target.get("outcome")
        if item_outcome is not None and item_outcome not in _TARGET_OUTCOMES:
            raise JournalError("JOURNAL_INVALID")
        status = target.get("http_status")
        if item_outcome == "http_response":
            if type(status) is not int or not 200 <= status <= 599:
                raise JournalError("JOURNAL_INVALID")
        elif status is not None:
            raise JournalError("JOURNAL_INVALID")
        elapsed = target.get("elapsed_ms")
        if elapsed is not None and (type(elapsed) is not int or not 0 <= elapsed <= 12000):
            raise JournalError("JOURNAL_INVALID")
    state = payload["state"]
    if state == "INIT":
        if any(
            value is not None
            for value in (digest, manifest_b64, outcome, target_count)
        ) or targets or payload["manifest_attempts_started"] != 0:
            raise JournalError("JOURNAL_INVALID")
    elif state == "OFFER_RECHECKED":
        if (
            digest is None
            or any(
                value is not None
                for value in (manifest_b64, outcome, target_count)
            )
            or targets
            or payload["manifest_attempts_started"] != 0
        ):
            raise JournalError("JOURNAL_INVALID")
    elif state == "MANIFEST_FETCH_STARTED":
        if (
            not 1 <= payload["manifest_attempts_started"] <= 3
            or digest is None
            or any(
                value is not None
                for value in (manifest_b64, outcome, target_count)
            )
            or targets
        ):
            raise JournalError("JOURNAL_INVALID")
    elif state in {
        "MANIFEST_VERIFIED",
        "ATTEMPT_STARTED",
        "RESULT_RECORDED",
    }:
        if (
            not 1 <= payload["manifest_attempts_started"] <= 3
            or digest is None
            or manifest_b64 is None
            or outcome != "retrieved"
            or type(target_count) is not int
            or not 1 <= target_count <= 10
        ):
            raise JournalError("JOURNAL_INVALID")
        target_states = [item["state"] for item in targets]
        if state == "MANIFEST_VERIFIED":
            valid_progress = all(item == "UNSTARTED" for item in target_states)
        elif state == "ATTEMPT_STARTED":
            valid_progress = (
                target_states.count("ATTEMPT_STARTED") == 1
                and all(
                    item == "RESULT_RECORDED"
                    for item in target_states[: target_states.index("ATTEMPT_STARTED")]
                )
                and all(
                    item == "UNSTARTED"
                    for item in target_states[target_states.index("ATTEMPT_STARTED") + 1 :]
                )
            )
        else:
            first_unstarted = next(
                (
                    index
                    for index, item in enumerate(target_states)
                    if item == "UNSTARTED"
                ),
                len(target_states),
            )
            valid_progress = (
                first_unstarted > 0
                and all(
                    item == "RESULT_RECORDED"
                    for item in target_states[:first_unstarted]
                )
                and all(
                    item == "UNSTARTED"
                    for item in target_states[first_unstarted:]
                )
            )
        if not valid_progress:
            raise JournalError("JOURNAL_INVALID")
    submission = payload["submission_id"]
    report_digest = payload["frozen_report_sha256"]
    report_b64 = payload["frozen_report_bytes_b64"]
    report_states = {
        "REPORT_FROZEN",
        "COMPOUND_COMPLETION_ACKED",
        "TERMINAL_STATUS",
    }
    if state in report_states:
        if outcome == "retrieved":
            if (
                not 1 <= payload["manifest_attempts_started"] <= 3
                or digest is None
                or manifest_b64 is None
                or type(target_count) is not int
                or not 1 <= target_count <= 10
                or any(item["state"] != "RESULT_RECORDED" for item in targets)
            ):
                raise JournalError("JOURNAL_INVALID")
        elif (
            digest is None
            or manifest_b64 is not None
            or target_count is not None
            or targets
        ):
            raise JournalError("JOURNAL_INVALID")
    has_any_report_field = any(
        value is not None for value in (submission, report_digest, report_b64)
    )
    if payload["state"] in report_states:
        if not has_any_report_field or outcome is None:
            raise JournalError("JOURNAL_INVALID")
    elif has_any_report_field:
        raise JournalError("JOURNAL_INVALID")
    if has_any_report_field:
        if (
            type(submission) is not str
            or _SUBMISSION_RE.fullmatch(submission) is None
            or type(report_digest) is not str
            or _SHA256_RE.fullmatch(report_digest) is None
            or type(report_b64) is not str
        ):
            raise JournalError("JOURNAL_INVALID")
        try:
            report_bytes = base64.b64decode(report_b64, validate=True)
        except (ValueError, TypeError):
            raise JournalError("JOURNAL_INVALID") from None
        if (
            not report_bytes
            or len(report_bytes) > 65536
            or hashlib.sha256(report_bytes).hexdigest() != report_digest
        ):
            raise JournalError("JOURNAL_INVALID")
        _decoded_frozen_report(payload, report_bytes)
    attempts = payload["completion_dispatch_attempts"]
    if type(attempts) is not int or not 0 <= attempts <= 2:
        raise JournalError("JOURNAL_INVALID")
    ack = payload["compound_ack"]
    if payload["state"] in {"COMPOUND_COMPLETION_ACKED", "TERMINAL_STATUS"}:
        if attempts < 1 or ack is None:
            raise JournalError("JOURNAL_INVALID")
        _validate_compound_ack(payload, ack)
    elif ack is not None:
        raise JournalError("JOURNAL_INVALID")
    terminal_status = payload["terminal_status"]
    if payload["state"] == "TERMINAL_STATUS":
        if terminal_status is None:
            raise JournalError("JOURNAL_INVALID")
        _validate_terminal_status(payload, terminal_status)
    elif terminal_status is not None:
        raise JournalError("JOURNAL_INVALID")
    if payload["state"] != "REPORT_FROZEN" and payload["state"] not in {
        "COMPOUND_COMPLETION_ACKED",
        "TERMINAL_STATUS",
    } and attempts != 0:
        raise JournalError("JOURNAL_INVALID")
    if _contains_secret(payload):
        raise JournalError("JOURNAL_INVALID")
    return payload


class _StableLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        flags = os.O_RDWR | os.O_CREAT
        for name in ("O_NOFOLLOW", "O_BINARY", "O_NOINHERIT"):
            flags |= getattr(os, name, 0)
        try:
            self.fd = os.open(str(path), flags, 0o600)
            if os.name != "nt":
                os.fchmod(self.fd, 0o600)
            info = os.fstat(self.fd)
            path_info = os.stat(str(path), follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            ):
                raise JournalError("JOURNAL_INVALID")
            if os.name == "nt":
                import msvcrt

                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                self.module = msvcrt
            else:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.module = fcntl
        except (OSError, JournalError):
            if hasattr(self, "fd"):
                os.close(self.fd)
            raise JournalError("JOURNAL_LOCKED") from None

    def close(self) -> None:
        try:
            if os.name == "nt":
                os.lseek(self.fd, 0, os.SEEK_SET)
                self.module.locking(self.fd, self.module.LK_UNLCK, 1)
            else:
                self.module.flock(self.fd, self.module.LOCK_UN)
        finally:
            os.close(self.fd)

    def __enter__(self) -> "_StableLock":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()


class TaskJournal:
    """One explicit durable journal binding; no default path is available."""

    def __init__(
        self,
        path: Any,
        *,
        task_id: str,
        local_claim_credential_handle: str,
        task_type: str,
        task_definition_version: str,
        task_definition_digest: str,
        fault_hook: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.path = _validate_journal_path(path)
        self.lock_path = _validate_journal_path(str(self.path) + ".lock")
        self.completion_lock_path = _validate_journal_path(
            str(self.path) + ".completion.lock"
        )
        try:
            self.task_id = validate_task_id(task_id)
        except Exception:
            raise JournalError("JOURNAL_INVALID") from None
        self.local_claim_credential_handle = _validated_identifier(
            local_claim_credential_handle, _HANDLE_RE
        )
        (
            self.task_type,
            self.task_definition_version,
            self.task_definition_digest,
        ) = _validated_definition_identity(
            task_type, task_definition_version, task_definition_digest
        )
        self.execution_id = derive_local_execution_id(
            self.task_id, self.local_claim_credential_handle
        )
        self._fault_hook = fault_hook

    def require_binding(
        self,
        *,
        task_id: Any,
        local_claim_credential_handle: Any,
        task_type: Any,
        task_definition_version: Any,
        task_definition_digest: Any,
    ) -> None:
        """Validate a caller's complete non-secret identity without journal I/O."""

        try:
            checked_task_id = validate_task_id(task_id)
        except Exception:
            raise JournalError("JOURNAL_INVALID") from None
        checked_handle = _validated_identifier(
            local_claim_credential_handle, _HANDLE_RE
        )
        checked_definition = _validated_definition_identity(
            task_type, task_definition_version, task_definition_digest
        )
        if (
            checked_task_id != self.task_id
            or checked_handle != self.local_claim_credential_handle
            or checked_definition
            != (
                self.task_type,
                self.task_definition_version,
                self.task_definition_digest,
            )
            or self.execution_id
            != derive_local_execution_id(checked_task_id, checked_handle)
        ):
            raise JournalError("JOURNAL_INVALID")

    @contextmanager
    def completion_operation_guard(self) -> Iterator[None]:
        """Hold the cross-process Completion guard across decision and I/O."""

        with _StableLock(self.completion_lock_path):
            yield

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _read_locked(self, *, allow_missing: bool = False) -> Optional[Dict[str, Any]]:
        flags = os.O_RDONLY
        for name in ("O_NOFOLLOW", "O_BINARY", "O_NOINHERIT"):
            flags |= getattr(os, name, 0)
        try:
            descriptor = os.open(str(self.path), flags)
        except FileNotFoundError:
            if allow_missing:
                return None
            raise JournalError("JOURNAL_MISSING") from None
        try:
            before = os.fstat(descriptor)
            path_info = os.stat(str(self.path), follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > JOURNAL_MAXIMUM_BYTES
                or (before.st_dev, before.st_ino) != (path_info.st_dev, path_info.st_ino)
                or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600)
            ):
                raise JournalError("JOURNAL_INVALID")
            content = bytearray()
            while len(content) <= JOURNAL_MAXIMUM_BYTES:
                chunk = os.read(descriptor, min(65536, JOURNAL_MAXIMUM_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            if (
                len(content) > JOURNAL_MAXIMUM_BYTES
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            ):
                raise JournalError("JOURNAL_INVALID")
        finally:
            os.close(descriptor)
        try:
            envelope = json.loads(
                bytes(content).decode("utf-8"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            raise JournalError("JOURNAL_INVALID") from None
        if type(envelope) is not dict or set(envelope) != {
            "schema_version",
            "payload",
            "checksum",
        }:
            raise JournalError("JOURNAL_INVALID")
        if envelope["schema_version"] != JOURNAL_SCHEMA_VERSION:
            raise JournalError("JOURNAL_INVALID")
        payload = _validate_payload(envelope["payload"])
        if envelope["checksum"] != _checksum(payload):
            raise JournalError("JOURNAL_INVALID")
        if (
            payload["task_id"] != self.task_id
            or payload["local_claim_credential_handle"]
            != self.local_claim_credential_handle
            or payload["execution_id"] != self.execution_id
            or payload["task_type"] != self.task_type
            or payload["task_definition_version"]
            != self.task_definition_version
            or payload["task_definition_digest"]
            != self.task_definition_digest
        ):
            raise JournalError("JOURNAL_INVALID")
        return payload

    def _write_locked(self, payload: Dict[str, Any]) -> None:
        _validate_payload(payload)
        envelope = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "payload": payload,
            "checksum": _checksum(payload),
        }
        try:
            encoded = jcs_canonical_bytes(envelope) + b"\n"
        except Exception:
            raise JournalError("JOURNAL_INVALID") from None
        if len(encoded) > JOURNAL_MAXIMUM_BYTES:
            raise JournalError("JOURNAL_INVALID")
        temporary_fd = -1
        temporary_name: Optional[str] = None
        replaced = False
        try:
            self._fault("before_temp_write")
            temporary_fd, temporary_name = tempfile.mkstemp(
                prefix=".%s." % self.path.name,
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            if os.name != "nt":
                os.fchmod(temporary_fd, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            self._fault("after_temp_write")
            os.fsync(temporary_fd)
            self._fault("after_file_fsync")
            os.close(temporary_fd)
            temporary_fd = -1
            # Both source and destination data handles are closed here.  The
            # stable sibling lock remains held across the replacement.
            self._fault("before_replace")
            os.replace(temporary_name, str(self.path))
            replaced = True
            self._fault("after_replace")
            if os.name != "nt":
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                directory_fd = os.open(str(self.path.parent), flags)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            self._fault("after_directory_fsync")
        except BaseException:
            if temporary_fd >= 0:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            if not replaced and temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass
            raise JournalPersistenceError() from None

    def create(self) -> JournalSnapshot:
        with _StableLock(self.lock_path):
            if self._read_locked(allow_missing=True) is not None:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload = _new_payload(
                self.task_id,
                self.local_claim_credential_handle,
                self.execution_id,
                self.task_type,
                self.task_definition_version,
                self.task_definition_digest,
            )
            self._write_locked(payload)
            return JournalSnapshot(dict(payload))

    def load(self) -> JournalSnapshot:
        with _StableLock(self.lock_path):
            payload = self._read_locked()
            assert payload is not None
            return JournalSnapshot(dict(payload))

    def _update(self, mutate: Callable[[Dict[str, Any]], None]) -> JournalSnapshot:
        with _StableLock(self.lock_path):
            payload = self._read_locked()
            assert payload is not None
            mutate(payload)
            payload["sequence"] += 1
            self._write_locked(payload)
            return JournalSnapshot(dict(payload))

    @staticmethod
    def _require_state(payload: Mapping[str, Any], *states: str) -> None:
        if payload["state"] not in states:
            raise JournalError("JOURNAL_STATE_CONFLICT")

    def mark_offer_rechecked(self, manifest_sha256: str) -> JournalSnapshot:
        """Atomically bind the at-T readiness digest before release I/O."""

        if (
            type(manifest_sha256) is not str
            or _SHA256_RE.fullmatch(manifest_sha256) is None
        ):
            raise JournalError("JOURNAL_INVALID")

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "INIT")
            if payload["manifest_sha256"] is not None:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["manifest_sha256"] = manifest_sha256
            payload["state"] = "OFFER_RECHECKED"

        return self._update(mutate)

    def start_manifest_attempt(self) -> JournalSnapshot:
        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "OFFER_RECHECKED", "MANIFEST_FETCH_STARTED")
            if payload["manifest_attempts_started"] >= 3:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["manifest_attempts_started"] += 1
            payload["state"] = "MANIFEST_FETCH_STARTED"

        return self._update(mutate)

    def bind_verified_manifest(
        self,
        manifest_sha256: str,
        target_count: int,
        *,
        manifest_bytes: bytes,
    ) -> JournalSnapshot:
        if type(manifest_sha256) is not str or _SHA256_RE.fullmatch(manifest_sha256) is None:
            raise JournalError("JOURNAL_INVALID")
        if type(target_count) is not int or not 1 <= target_count <= 10:
            raise JournalError("JOURNAL_INVALID")
        if (
            type(manifest_bytes) is not bytes
            or not manifest_bytes
            or len(manifest_bytes) > 32768
            or hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256
        ):
            raise JournalError("JOURNAL_INVALID")

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "MANIFEST_FETCH_STARTED")
            if payload["manifest_sha256"] != manifest_sha256:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["manifest_bytes_b64"] = base64.b64encode(manifest_bytes).decode("ascii")
            payload["manifest_fetch_outcome"] = "retrieved"
            payload["target_count"] = target_count
            payload["targets"] = [
                {"position": position, "state": "UNSTARTED"}
                for position in range(target_count)
            ]
            payload["state"] = "MANIFEST_VERIFIED"

        return self._update(mutate)

    def verified_manifest_bytes(self) -> bytes:
        payload = self.load().payload
        value = payload["manifest_bytes_b64"]
        if value is None:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        return base64.b64decode(value, validate=True)

    def mark_target_attempt_started(self, position: int) -> JournalSnapshot:
        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "MANIFEST_VERIFIED", "RESULT_RECORDED")
            if type(position) is not int or not 0 <= position < len(payload["targets"]):
                raise JournalError("JOURNAL_STATE_CONFLICT")
            if any(
                item["state"] != "RESULT_RECORDED"
                for item in payload["targets"][:position]
            ) or payload["targets"][position]["state"] != "UNSTARTED":
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["targets"][position] = {
                "position": position,
                "state": "ATTEMPT_STARTED",
            }
            payload["state"] = "ATTEMPT_STARTED"

        return self._update(mutate)

    def record_target_result(
        self,
        position: int,
        outcome: str,
        *,
        http_status: Optional[int] = None,
        elapsed_ms: Optional[int] = None,
    ) -> JournalSnapshot:
        if outcome not in _TARGET_OUTCOMES:
            raise JournalError("JOURNAL_INVALID")

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "ATTEMPT_STARTED", "MANIFEST_VERIFIED", "RESULT_RECORDED")
            if type(position) is not int or not 0 <= position < len(payload["targets"]):
                raise JournalError("JOURNAL_STATE_CONFLICT")
            prior = payload["targets"][position]
            if outcome.startswith("not_attempted_"):
                if prior["state"] != "UNSTARTED":
                    raise JournalError("JOURNAL_STATE_CONFLICT")
            elif outcome == "interrupted_indeterminate":
                if prior["state"] != "ATTEMPT_STARTED":
                    raise JournalError("JOURNAL_STATE_CONFLICT")
            elif prior["state"] != "ATTEMPT_STARTED":
                raise JournalError("JOURNAL_STATE_CONFLICT")
            item: Dict[str, Any] = {
                "position": position,
                "state": "RESULT_RECORDED",
                "outcome": outcome,
            }
            if outcome == "http_response":
                if type(http_status) is not int or not 200 <= http_status <= 599:
                    raise JournalError("JOURNAL_INVALID")
                item["http_status"] = http_status
            elif http_status is not None:
                raise JournalError("JOURNAL_INVALID")
            if elapsed_ms is not None:
                if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 12000:
                    raise JournalError("JOURNAL_INVALID")
                item["elapsed_ms"] = elapsed_ms
            payload["targets"][position] = item
            payload["state"] = "RESULT_RECORDED"

        return self._update(mutate)

    def freeze_report(
        self,
        report_bytes: bytes,
        *,
        submission_id: str,
        manifest_fetch_outcome: str,
    ) -> JournalSnapshot:
        if (
            type(report_bytes) is not bytes
            or len(report_bytes) > 65536
            or type(submission_id) is not str
            or _SUBMISSION_RE.fullmatch(submission_id) is None
            or manifest_fetch_outcome not in _MANIFEST_OUTCOMES
        ):
            raise JournalError("JOURNAL_INVALID")

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(
                payload,
                "OFFER_RECHECKED",
                "MANIFEST_FETCH_STARTED",
                "MANIFEST_VERIFIED",
                "RESULT_RECORDED",
            )
            if manifest_fetch_outcome == "retrieved" and any(
                item["state"] != "RESULT_RECORDED" for item in payload["targets"]
            ):
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["manifest_fetch_outcome"] = manifest_fetch_outcome
            payload["submission_id"] = submission_id
            payload["frozen_report_sha256"] = hashlib.sha256(report_bytes).hexdigest()
            payload["frozen_report_bytes_b64"] = base64.b64encode(report_bytes).decode("ascii")
            payload["state"] = "REPORT_FROZEN"

        return self._update(mutate)

    def frozen_report_bytes(self) -> bytes:
        snapshot = self.load().payload
        if snapshot["state"] not in {
            "REPORT_FROZEN",
            "COMPOUND_COMPLETION_ACKED",
            "TERMINAL_STATUS",
        }:
            raise JournalError("JOURNAL_STATE_CONFLICT")
        return base64.b64decode(snapshot["frozen_report_bytes_b64"], validate=True)

    def mark_completion_dispatch_attempted(self) -> JournalSnapshot:
        """Durably reserve one of two permitted exact-byte dispatches.

        The canonical state remains ``REPORT_FROZEN``.  Once this auxiliary
        marker is durable, every restart must resolve status first and must
        never treat the Completion as undispatched.
        """

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "REPORT_FROZEN")
            if payload["completion_dispatch_attempts"] >= 2:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["completion_dispatch_attempts"] += 1

        return self._update(mutate)

    def mark_compound_completion_acked(
        self, acknowledgement: Any
    ) -> JournalSnapshot:
        """Atomically bind a durable receipt/status and cross the terminal boundary."""

        facts = _normalise_acknowledgement(acknowledgement)

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "REPORT_FROZEN")
            if payload["completion_dispatch_attempts"] < 1:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload["compound_ack"] = _validate_compound_ack(payload, facts)
            payload["state"] = "COMPOUND_COMPLETION_ACKED"

        return self._update(mutate)

    def compound_acknowledgement_facts(self) -> Mapping[str, str]:
        payload = self.load().payload
        self._require_state(payload, "COMPOUND_COMPLETION_ACKED", "TERMINAL_STATUS")
        return dict(_validate_compound_ack(payload, payload["compound_ack"]))

    def mark_terminal_status(self, status: Any) -> JournalSnapshot:
        """Persist one authoritative bound terminal status observation."""

        terminal_status = _normalise_terminal_status(status)

        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, "COMPOUND_COMPLETION_ACKED")
            payload["terminal_status"] = _validate_terminal_status(
                payload, terminal_status
            )
            payload["state"] = "TERMINAL_STATUS"

        return self._update(mutate)

    def _transition(self, before: str, after: str) -> JournalSnapshot:
        def mutate(payload: Dict[str, Any]) -> None:
            self._require_state(payload, before)
            payload["state"] = after

        return self._update(mutate)

    def resume_disposition(self) -> str:
        """Return the only safe action after an interrupted process."""

        payload = self.load().payload
        if payload["state"] == "MANIFEST_FETCH_STARTED":
            return "release_interrupted"
        if payload["state"] == "ATTEMPT_STARTED":
            return "target_interrupted_indeterminate"
        if (
            payload["state"] == "REPORT_FROZEN"
            and payload["completion_dispatch_attempts"] > 0
        ):
            return "completion_status_first"
        if payload["state"] in {"COMPOUND_COMPLETION_ACKED", "TERMINAL_STATUS"}:
            return "status_only"
        if payload["state"] == "REPORT_FROZEN":
            return "completion_dispatch"
        return "resume_checkpoint"


__all__ = [
    "JOURNAL_CHECKSUM_DOMAIN",
    "JOURNAL_MAXIMUM_BYTES",
    "JOURNAL_SCHEMA_VERSION",
    "JournalError",
    "JournalPersistenceError",
    "JournalSnapshot",
    "TaskJournal",
    "derive_local_execution_id",
]
