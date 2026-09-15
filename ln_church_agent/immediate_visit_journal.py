"""Private, durable storage for one Claim's single GET and frozen report.

The existing private-path, descriptor and cross-process lock primitives are
reused without entering the scheduled Task state machine. Claim credentials
are kept in a separate private file; the ordinary journal contains no token.
"""

from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Dict, Iterator, Optional

from ._private_file_io import fsync_directory, read_bounded, write_all
from .task_journal import (
    JournalError, JournalPersistenceError, _StableLock, _validate_journal_path,
)
from .immediate_visit_models import (
    FrozenImmediateVisitReport, ImmediateVisitClaimCredential,
)
from .immediate_visit_profile import jcs_bytes


_SCHEMA = "ln_church.immediate_visit_journal.v1"
_MAX_BYTES = 256 * 1024


def _checked_claim(claim: Any) -> ImmediateVisitClaimCredential:
    try:
        return ImmediateVisitClaimCredential.model_validate(claim)
    except Exception:
        pass
    raise JournalError("JOURNAL_INVALID")


def _private_boundary(function: Any) -> Any:
    """Detach decoder/validation/OS exceptions from public error objects."""
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except JournalPersistenceError:
            failure = JournalPersistenceError()
        except JournalError as error:
            failure = JournalError(error.code)
        except Exception:
            failure = JournalError("JOURNAL_INVALID")
        raise failure
    return wrapped


def _pairs(pairs: Any) -> Dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError


def _read(path: Path, *, missing: bool = False) -> Optional[Dict[str, Any]]:
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_BINARY", "O_NOINHERIT"):
        flags |= getattr(os, name, 0)
    try:
        descriptor = os.open(str(path), flags)
    except FileNotFoundError:
        if missing:
            return None
        raise JournalError("JOURNAL_MISSING") from None
    except OSError:
        raise JournalError("JOURNAL_INVALID") from None
    try:
        info = os.fstat(descriptor)
        at_path = os.stat(str(path), follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= _MAX_BYTES
                or (info.st_dev, info.st_ino) != (at_path.st_dev, at_path.st_ino)
                or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)):
            raise JournalError("JOURNAL_INVALID")
        content = read_bounded(descriptor, _MAX_BYTES)
        if len(content) > _MAX_BYTES:
            raise JournalError("JOURNAL_INVALID")
    except OSError:
        raise JournalError("JOURNAL_INVALID") from None
    finally:
        os.close(descriptor)
    try:
        envelope = json.loads(bytes(content).decode("utf-8"),
                              object_pairs_hook=_pairs,
                              parse_constant=_invalid_constant)
        if type(envelope) is not dict or set(envelope) != {"payload", "sha256"}:
            raise ValueError
        payload = envelope["payload"]
        if (type(payload) is not dict or hashlib.sha256(jcs_bytes(payload)).hexdigest()
                != envelope["sha256"]):
            raise ValueError
        return payload
    except Exception:
        pass
    raise JournalError("JOURNAL_INVALID")


def _write(path: Path, payload: Dict[str, Any]) -> None:
    descriptor = -1
    temporary = None
    try:
        encoded = jcs_bytes({"payload": payload,
                             "sha256": hashlib.sha256(jcs_bytes(payload)).hexdigest()})
        if len(encoded) > _MAX_BYTES:
            raise ValueError
        descriptor, temporary = tempfile.mkstemp(prefix=".%s." % path.name,
                                                 suffix=".tmp", dir=str(path.parent))
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, str(path))
        temporary = None
        fsync_directory(path.parent)
    except BaseException:
        raise JournalPersistenceError() from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


class ImmediateVisitJournal:
    """Use one private directory consistently for every executor of a Claim.

    On Windows the directory must be under LOCALAPPDATA/ln-church-agent/claims,
    preserving the existing private-storage boundary. The caller creates it.
    """

    @_private_boundary
    def __init__(self, directory: Any, claim: ImmediateVisitClaimCredential) -> None:
        snapshot = _checked_claim(claim)
        self.task_id = snapshot.task_id
        self.execution_id = snapshot.execution_id
        self._claim_binding = hashlib.sha256(jcs_bytes(snapshot.model_dump(mode="json"))).hexdigest()
        self.path, self.credential_path = self._paths(directory, self.task_id, self.execution_id)
        self.lock_path = _validate_journal_path(str(self.path) + ".lock")
        self.fetch_lock_path = _validate_journal_path(str(self.path) + ".fetch.lock")
        self.completion_lock_path = _validate_journal_path(str(self.path) + ".completion.lock")
        with _StableLock(self.lock_path):
            data = _read(self.path, missing=True)
            old = _read(self.credential_path, missing=True)
            private = snapshot._private_payload()
            # Initialize the no-GET record first. Once a credential exists, a
            # missing journal is lost history, never permission for a new GET.
            if data is None:
                if old is not None:
                    raise JournalError("JOURNAL_MISSING")
                _write(self.path, self._initial())
            else:
                self._validate(data)
            if old is None:
                _write(self.credential_path, private)
            elif jcs_bytes(old) != jcs_bytes(private):
                raise JournalError("JOURNAL_STATE_CONFLICT")

    def __repr__(self) -> str:
        return "ImmediateVisitJournal(<private>)"

    @staticmethod
    def _paths(directory: Any, task_id: str, execution_id: str) -> Any:
        key = hashlib.sha256(jcs_bytes([task_id, execution_id])).hexdigest()
        root = Path(directory)
        return (_validate_journal_path(root / (key + ".json")),
                _validate_journal_path(root / (key + ".credential.json")))

    @classmethod
    @_private_boundary
    def load_claim(cls, directory: Any, task_id: str, execution_id: str) -> ImmediateVisitClaimCredential:
        path, credential_path = cls._paths(directory, task_id, execution_id)
        with _StableLock(_validate_journal_path(str(path) + ".lock")):
            claim = _checked_claim(_read(credential_path))
            if claim.task_id != task_id or claim.execution_id != execution_id:
                raise JournalError("JOURNAL_STATE_CONFLICT")
            return claim

    @_private_boundary
    def require_binding(self, claim: ImmediateVisitClaimCredential) -> None:
        snapshot = _checked_claim(claim)
        if (snapshot.task_id != self.task_id or snapshot.execution_id != self.execution_id
                or hashlib.sha256(jcs_bytes(snapshot.model_dump(mode="json"))).hexdigest()
                != self._claim_binding):
            raise JournalError("JOURNAL_STATE_CONFLICT")

    def _initial(self) -> Dict[str, Any]:
        return dict(schema_version=_SCHEMA, task_id=self.task_id,
                    execution_id=self.execution_id, claim_sha256=self._claim_binding,
                    endpoint_id=None, fetch_started_at=None, observation=None,
                    report=None, report_sha256=None, dispatch_started=False,
                    accepted=False, rejection=None)

    def _validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        initial = self._initial()
        if set(data) != set(initial) or any(data[key] != initial[key] for key in
                ("schema_version", "task_id", "execution_id", "claim_sha256")):
            raise JournalError("JOURNAL_INVALID")
        if type(data["dispatch_started"]) is not bool or type(data["accepted"]) is not bool:
            raise JournalError("JOURNAL_INVALID")
        if data["report"] is not None:
            try:
                report = FrozenImmediateVisitReport.from_bytes(data["report"].encode("utf-8"))
                if (report.task_id != self.task_id or report.execution_id != self.execution_id
                        or report.endpoint_id != data["endpoint_id"]
                        or report.report_sha256 != data["report_sha256"]):
                    raise ValueError
            except Exception:
                raise JournalError("JOURNAL_INVALID") from None
        elif data["report_sha256"] is not None or data["dispatch_started"] or data["accepted"]:
            raise JournalError("JOURNAL_INVALID")
        return data

    def _load(self) -> Dict[str, Any]:
        return self._validate(_read(self.path))

    @contextmanager
    def fetch_operation_guard(self) -> Iterator[None]:
        with _StableLock(self.fetch_lock_path):
            yield

    @contextmanager
    def completion_operation_guard(self) -> Iterator[None]:
        with _StableLock(self.completion_lock_path):
            yield

    @_private_boundary
    def load_report(self, claim: ImmediateVisitClaimCredential) -> Optional[FrozenImmediateVisitReport]:
        self.require_binding(claim)
        with _StableLock(self.lock_path):
            data = self._load()
            return (None if data["report"] is None else
                    FrozenImmediateVisitReport.from_bytes(data["report"].encode("utf-8")))

    @_private_boundary
    def begin_fetch(self, claim: ImmediateVisitClaimCredential, endpoint_id: str,
                    started_at: str) -> Dict[str, Any]:
        """Call with the fetch guard held; persist intent before target I/O."""
        self.require_binding(claim)
        if endpoint_id not in tuple(endpoint.endpoint_id for endpoint in claim.endpoints):
            raise JournalError("JOURNAL_STATE_CONFLICT")
        with _StableLock(self.lock_path):
            data = self._load()
            if data["endpoint_id"] is not None:
                if data["endpoint_id"] != endpoint_id:
                    raise JournalError("JOURNAL_STATE_CONFLICT")
                return dict(data, start_permitted=False)
            data["endpoint_id"] = endpoint_id
            data["fetch_started_at"] = started_at
            _write(self.path, data)
            return dict(data, start_permitted=True)

    def save_observation(self, claim: ImmediateVisitClaimCredential,
                         report: FrozenImmediateVisitReport) -> None:
        self.prepare_report(claim, report)

    @_private_boundary
    def prepare_report(self, claim: ImmediateVisitClaimCredential,
                       report: FrozenImmediateVisitReport) -> FrozenImmediateVisitReport:
        self.require_binding(claim)
        report = FrozenImmediateVisitReport.from_bytes(report.canonical_bytes)
        if (report.task_id != claim.task_id or report.execution_id != claim.execution_id
                or report.profile_id != claim.profile_id
                or report.endpoint_id not in tuple(item.endpoint_id for item in claim.endpoints)):
            raise JournalError("JOURNAL_STATE_CONFLICT")
        with _StableLock(self.lock_path):
            data = self._load()
            if data["report"] is not None:
                if data["report"].encode("utf-8") != report.canonical_bytes:
                    raise JournalError("JOURNAL_STATE_CONFLICT")
                return report
            if data["endpoint_id"] not in (None, report.endpoint_id):
                raise JournalError("JOURNAL_STATE_CONFLICT")
            payload = json.loads(report.canonical_bytes)
            data.update(endpoint_id=report.endpoint_id, observation=payload["observation"],
                        fetch_started_at=payload["observation"]["fetch_started_at"],
                        report=report.canonical_bytes.decode("utf-8"),
                        report_sha256=report.report_sha256)
            _write(self.path, data)
            return report

    @_private_boundary
    def completion_started(self, claim: ImmediateVisitClaimCredential,
                           report: FrozenImmediateVisitReport) -> bool:
        self.prepare_report(claim, report)
        with _StableLock(self.lock_path):
            return self._load()["dispatch_started"]

    @_private_boundary
    def correct_unaccepted_report(self, claim: ImmediateVisitClaimCredential,
                                  corrected: FrozenImmediateVisitReport) -> FrozenImmediateVisitReport:
        """Explicit correction after a definite invalid_request, using the same GET.

        This does not assert that time remains: the Venue alone decides whether
        a corrected report is durably accepted before the Claim deadline.
        An unknown dispatch or accepted report cannot authorize replacement.
        """
        self.require_binding(claim)
        corrected = FrozenImmediateVisitReport.from_bytes(corrected.canonical_bytes)
        with self.completion_operation_guard():
            with _StableLock(self.lock_path):
                data = self._load()
                if data["accepted"] or data["rejection"] != "invalid_request" or data["report"] is None:
                    raise JournalError("JOURNAL_STATE_CONFLICT")
                old = json.loads(data["report"])
                new = json.loads(corrected.canonical_bytes)
                # Correction must preserve the acquisition, its diagnostic times,
                # and all authoritative Claim/endpoint/profile bindings.
                if any(new[key] != old[key] for key in old if key != "submission_id"):
                    raise JournalError("JOURNAL_STATE_CONFLICT")
                data.update(report=corrected.canonical_bytes.decode("utf-8"),
                            report_sha256=corrected.report_sha256,
                            dispatch_started=False, rejection=None)
                _write(self.path, data)
                return corrected

    @_private_boundary
    def record_dispatch(self, claim: ImmediateVisitClaimCredential,
                        report: FrozenImmediateVisitReport) -> None:
        self.prepare_report(claim, report)
        with _StableLock(self.lock_path):
            data = self._load()
            data.update(dispatch_started=True, rejection=None)
            _write(self.path, data)

    @_private_boundary
    def record_result(self, claim: ImmediateVisitClaimCredential,
                      report: FrozenImmediateVisitReport, result: Any) -> None:
        self.prepare_report(claim, report)
        with _StableLock(self.lock_path):
            data = self._load()
            if result.state == "accepted":
                data.update(accepted=True, rejection=None)
            elif result.state == "rejected" and not data["accepted"]:
                data["rejection"] = ("invalid_request" if result.error_code == "invalid_request" else None)
            _write(self.path, data)
