import argparse
import requests
import httpx
import re
import os
import json
import json as _task_json
import stat
import sys as _task_sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, List, Tuple, Type
from .models import InspectResult, SettlementOption, ObservatoryMetadata
from .challenges import parse_challenge_from_response
from .exceptions import NoValidPaymentChallengeError, PaymentChallengeError
from .app_inspect import detect_commerce_surface, detect_app_surface, build_commerce_guidance
from .grant_signals import detect_grant_signals
from .models import GrantSignalObservation
from .inspect_transport import InspectTransportError, _inspect_request
from .redaction import _contains_inspect_secret_material, redact_inspect_public_url


_TASK_FILE_MAX_BYTES = 256 * 1024
# A checkpoint wraps one wire-valid Observation plus the bounded public
# snapshot from one CLI-valid Claim credential and fixed restart metadata.
# Keep its private local envelope separate and finite without widening any
# public wire, Observation-file, or credential-file limit.
_TASK_CHECKPOINT_FILE_MAX_BYTES = 3 * _TASK_FILE_MAX_BYTES
_TASK_CREDENTIAL_SCHEMA = "ln_church.task_claim_credential_file.v1"
_TASK_FIXED_ORIGIN = "https://kari.mayim-mayim.com"
_TASK_ERROR_CODES = frozenset(
    {
        "CLAIM_OUTCOME_UNKNOWN",
        "SUBMISSION_OUTCOME_UNKNOWN",
        "COMPLETION_OUTCOME_UNKNOWN",
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
        "invalid_request",
        "unsupported_task_type",
        "domain_mismatch",
        "claim_token_invalid",
        "task_not_found",
        "task_not_open",
        "task_state_conflict",
        "submission_conflict",
        "claim_lease_expired",
        "payload_too_large",
        "rate_limited",
        "internal_error",
    }
)
_TASK_SECRET_FIELD_NAMES = frozenset(
    {
        "claimtoken",
        "claim_token",
        "claim-token",
        "x_ln_task_claim_token",
        "x-ln-task-claim-token",
    }
)


def _task_cli_error(code: Any) -> None:
    """Exit with a finite error code and no remote or exception text."""

    safe_code = code if type(code) is str and code in _TASK_ERROR_CODES else (
        "TASK_TRANSPORT_ERROR"
    )
    _task_sys.stderr.write("Task error: %s\n" % safe_code)
    raise SystemExit(2)


class _TaskArgumentParser(argparse.ArgumentParser):
    """Keep Task parse failures finite and free of raw argv values."""

    def error(self, message: str) -> None:
        if _task_sys.argv[1:2] == ["task"]:
            _task_cli_error("invalid_request")
        super().error(message)


def _task_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _task_public_payload(value: Any) -> Any:
    """Build a defensive public representation that drops credential fields."""

    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if type(value) is dict:
        public: Dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            compact = normalized.replace("-", "").replace("_", "")
            if (
                normalized in _TASK_SECRET_FIELD_NAMES
                or compact in {"claimtoken", "xlntaskclaimtoken"}
            ):
                continue
            public[str(key)] = _task_public_payload(item)
        return public
    if type(value) is list:
        return [_task_public_payload(item) for item in value]
    if type(value) is tuple:
        return [_task_public_payload(item) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise ValueError("TASK_RESPONSE_INVALID")


def _task_active_credential_payload(credential: Any) -> Dict[str, Any]:
    """Explicit secret-bearing codec used only for the private claim file."""

    try:
        payload = credential._to_private_file_payload()
    except Exception:
        raise ValueError("TASK_CREDENTIAL_INVALID") from None
    if type(payload) is not dict:
        raise ValueError("TASK_CREDENTIAL_INVALID")
    return payload


def _task_credential_from_payload(
    payload: Dict[str, Any],
    credential_type: Type[Any],
) -> Any:
    if type(payload) is not dict:
        raise ValueError("TASK_CREDENTIAL_INVALID")
    try:
        return credential_type._from_private_file_payload(payload)
    except Exception:
        raise ValueError("TASK_CREDENTIAL_INVALID") from None


def _task_tombstone(task_id: str) -> Dict[str, Any]:
    return {
        "schema_version": _TASK_CREDENTIAL_SCHEMA,
        "state": "CLAIM_OUTCOME_UNKNOWN",
        "api_origin": _TASK_FIXED_ORIGIN,
        "task_id": task_id,
        "created_at": _task_now_rfc3339(),
    }


def _reject_task_secret_cli_arguments(argv: List[str]) -> None:
    """Reject token-like Task options without letting argparse echo a secret."""

    if not argv or argv[0] != "task":
        return
    for argument in argv[1:]:
        if type(argument) is not str or not argument.startswith("-"):
            continue
        option = argument.split("=", 1)[0].lstrip("-")
        compact = option.lower().replace("-", "").replace("_", "")
        if compact in {"claimtoken", "xlntaskclaimtoken"}:
            _task_cli_error("TASK_CREDENTIAL_INVALID")


def _windows_original_ancestors(path: Any) -> Tuple[Any, ...]:
    """Return the lexical Windows ancestry, including the target itself."""

    return tuple(reversed(path.parents)) + (path,)


def _reject_windows_reparse_path(
    path: Path,
    *,
    require_claims_root: bool,
) -> Path:
    raw = str(path)
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise ValueError("TASK_CREDENTIAL_INVALID")

    # Build absolute lexical paths without following junctions.  Resolving
    # first would erase the very reparse points this boundary must reject.
    required_root = None
    if require_claims_root:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if (
            not local_app_data
            or local_app_data.startswith("\\\\")
            or local_app_data.startswith("//")
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        required_root = Path(
            os.path.abspath(
                os.path.join(
                    local_app_data, "ln-church-agent", "claims"
                )
            )
        )
    candidate = Path(os.path.abspath(raw))
    if (
        str(candidate).startswith("\\\\")
        or not candidate.name
    ):
        raise ValueError("TASK_CREDENTIAL_INVALID")
    if required_root is not None:
        if str(required_root).startswith("\\\\"):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        try:
            candidate.parent.relative_to(required_root)
        except (TypeError, ValueError):
            raise ValueError("TASK_CREDENTIAL_INVALID") from None

    import ctypes

    kernel32 = ctypes.windll.kernel32
    get_attributes = kernel32.GetFileAttributesW
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint32
    invalid_attributes = 0xFFFFFFFF
    reparse_point = 0x0400
    drive_remote = 4

    checked_paths = (
        (required_root, candidate)
        if required_root is not None
        else (candidate,)
    )
    for checked in checked_paths:
        anchor = checked.anchor
        if (
            not anchor
            or anchor.startswith("\\\\")
            or int(get_drive_type(anchor)) == drive_remote
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")

    def reject_reparse_ancestors(target: Path) -> None:
        # Inspect the drive root and every original component without first
        # resolving it.  This includes LOCALAPPDATA and the claims root.
        for current in _windows_original_ancestors(target):
            attributes = int(get_attributes(str(current)))
            if attributes == invalid_attributes or attributes & reparse_point:
                raise ValueError("TASK_CREDENTIAL_INVALID")

    if required_root is not None:
        reject_reparse_ancestors(required_root)
    reject_reparse_ancestors(candidate.parent)

    # If the final file already exists (Submit/Complete), it too must not be a
    # symlink or other reparse point.  Absence is expected before Claim's
    # create-exclusive open.
    final_attributes = int(get_attributes(str(candidate)))
    if (
        final_attributes != invalid_attributes
        and final_attributes & reparse_point
    ):
        raise ValueError("TASK_CREDENTIAL_INVALID")

    # Only after the original path has passed the no-reparse scan may we
    # resolve it for a second containment check.  Re-scan afterwards to catch
    # an ancestor changed during resolution.
    resolved_parent = candidate.parent.resolve(strict=True)
    resolved_root = None
    if required_root is not None:
        resolved_root = required_root.resolve(strict=True)
        try:
            resolved_parent.relative_to(resolved_root)
        except (TypeError, ValueError):
            raise ValueError("TASK_CREDENTIAL_INVALID") from None
        reject_reparse_ancestors(required_root)
    reject_reparse_ancestors(candidate.parent)

    resolved_paths = (
        (resolved_root, resolved_parent)
        if resolved_root is not None
        else (resolved_parent,)
    )
    for current in resolved_paths:
        attributes = int(get_attributes(str(current)))
        if attributes == invalid_attributes or attributes & reparse_point:
            raise ValueError("TASK_CREDENTIAL_INVALID")
    return resolved_parent / candidate.name


def _validated_task_file_path(
    path: str,
    *,
    require_claims_root: bool = True,
) -> Path:
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("TASK_CREDENTIAL_INVALID")
    candidate = Path(path)
    if os.name == "nt":
        return _reject_windows_reparse_path(
            candidate,
            require_claims_root=require_claims_root,
        )

    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError("TASK_CREDENTIAL_INVALID")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current = current / part
        info = os.lstat(str(current))
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise ValueError("TASK_CREDENTIAL_INVALID")
    parent_info = os.lstat(str(parent))
    if (
        parent_info.st_mode & 0o022
        and not parent_info.st_mode & stat.S_ISVTX
    ):
        raise ValueError("TASK_CREDENTIAL_INVALID")
    if (
        hasattr(os, "geteuid")
        and parent_info.st_uid != os.geteuid()
        and not parent_info.st_mode & stat.S_ISVTX
    ):
        raise ValueError("TASK_CREDENTIAL_INVALID")
    return absolute


class _TaskCredentialReservation:
    """Create-only claim file kept on one descriptor through final fsync."""

    def __init__(self, path: str) -> None:
        self.path = _validated_task_file_path(path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOINHERIT"):
            flags |= os.O_NOINHERIT
        self.fd = os.open(str(self.path), flags, 0o600)
        self.closed = False
        try:
            info = os.fstat(self.fd)
            self.identity = (info.st_dev, info.st_ino)
            if os.name != "nt":
                os.fchmod(self.fd, 0o600)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("TASK_CREDENTIAL_INVALID")
            self._require_identity()
        except Exception:
            try:
                self.remove_own_reservation()
            except (OSError, ValueError):
                self.close()
            except Exception:
                self.close()
                pass
            raise

    def _require_identity(self) -> None:
        if self.closed:
            raise ValueError("TASK_CREDENTIAL_INVALID")
        info = os.fstat(self.fd)
        path_info = os.stat(str(self.path), follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != self.identity
            or not stat.S_ISREG(path_info.st_mode)
            or path_info.st_nlink != 1
            or (path_info.st_dev, path_info.st_ino) != self.identity
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("TASK_CREDENTIAL_INVALID")

    def write_payload(self, payload: Dict[str, Any]) -> None:
        self._require_identity()
        try:
            encoded = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("TASK_CREDENTIAL_INVALID") from None
        if len(encoded) > _TASK_FILE_MAX_BYTES:
            raise ValueError("TASK_CREDENTIAL_INVALID")
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.ftruncate(self.fd, 0)
        view = memoryview(encoded)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(self.fd)
        self._require_identity()

    def close(self) -> None:
        if not self.closed:
            os.close(self.fd)
            self.closed = True

    def scrub_with_tombstone(self, payload: Dict[str, Any]) -> None:
        """Best-effort secret removal through the original descriptor."""

        if self.closed:
            return
        info = os.fstat(self.fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != self.identity
        ):
            return
        encoded = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.ftruncate(self.fd, 0)
        view = memoryview(encoded)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(self.fd)

    def remove_own_reservation(self) -> None:
        self._require_identity()
        if os.name == "nt":
            identity = self.identity
            self.close()
            current = os.stat(str(self.path), follow_symlinks=False)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != identity
            ):
                raise ValueError("TASK_CREDENTIAL_INVALID")
            os.unlink(str(self.path))
        else:
            os.unlink(str(self.path))
            self.close()


class _TaskCheckpointFile(_TaskCredentialReservation):
    """Private restart metadata held on one verified descriptor."""

    def __init__(self, path: str) -> None:
        self.path = _validated_task_file_path(path)
        base_flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            base_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            base_flags |= os.O_BINARY
        if hasattr(os, "O_NOINHERIT"):
            base_flags |= os.O_NOINHERIT
        self.closed = False
        self.created_new = False
        self.written = False
        self.locked = False
        self._lock_module = None
        try:
            self.fd = os.open(
                str(self.path),
                base_flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            self.created_new = True
        except FileExistsError:
            self.fd = os.open(str(self.path), base_flags)
        try:
            info = os.fstat(self.fd)
            self.identity = (info.st_dev, info.st_ino)
            self._acquire_exclusive_lock()
            if self.created_new and os.name != "nt":
                os.fchmod(self.fd, 0o600)
            self._require_identity()
        except Exception:
            try:
                if self.created_new:
                    self.remove_own_reservation()
                else:
                    self.close()
            except Exception:
                self.close()
            raise

    def _acquire_exclusive_lock(self) -> None:
        self._lock_module = self._lock_descriptor(self.fd)
        self.locked = True

    @staticmethod
    def _lock_descriptor(descriptor: int) -> Any:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return msvcrt
        else:
            import fcntl

            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
            return fcntl

    @staticmethod
    def _unlock_descriptor(descriptor: int, lock_module: Any) -> None:
        if os.name == "nt":
            os.lseek(descriptor, 0, os.SEEK_SET)
            lock_module.locking(
                descriptor,
                lock_module.LK_UNLCK,
                1,
            )
        else:
            lock_module.flock(
                descriptor,
                lock_module.LOCK_UN,
            )

    def _release_exclusive_lock(self) -> None:
        if not self.locked:
            return
        try:
            self._unlock_descriptor(
                self.fd,
                self._lock_module,
            )
        finally:
            self.locked = False

    def _require_identity(self) -> None:
        super()._require_identity()
        info = os.fstat(self.fd)
        if (
            os.name != "nt"
            and hasattr(os, "geteuid")
            and info.st_uid != os.geteuid()
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")

    def read_payload(self) -> Dict[str, Any]:
        self._require_identity()
        before = os.fstat(self.fd)
        if (
            before.st_size <= 0
            or before.st_size > _TASK_CHECKPOINT_FILE_MAX_BYTES
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        os.lseek(self.fd, 0, os.SEEK_SET)
        content = bytearray()
        while len(content) <= _TASK_CHECKPOINT_FILE_MAX_BYTES:
            chunk = os.read(
                self.fd,
                min(
                    64 * 1024,
                    _TASK_CHECKPOINT_FILE_MAX_BYTES + 1 - len(content),
                ),
            )
            if not chunk:
                break
            content.extend(chunk)
        self._require_identity()
        after = os.fstat(self.fd)
        if (
            (before.st_dev, before.st_ino)
            != (after.st_dev, after.st_ino)
            or len(content) > _TASK_CHECKPOINT_FILE_MAX_BYTES
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        parse_failed = False
        value: Any = None
        try:
            value = json.loads(
                bytes(content).decode("utf-8"),
                object_pairs_hook=_reject_task_json_object_pairs,
                parse_constant=_reject_task_json_constant,
            )
        except (
            UnicodeDecodeError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            parse_failed = True
        if parse_failed:
            content.clear()
            value = None
            raise ValueError("TASK_CREDENTIAL_INVALID")
        if type(value) is not dict:
            content.clear()
            value = None
            raise ValueError("TASK_CREDENTIAL_INVALID")
        return value

    def write_payload(self, payload: Dict[str, Any]) -> None:
        self._require_identity()
        try:
            encoded = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("TASK_CREDENTIAL_INVALID") from None
        if len(encoded) > _TASK_CHECKPOINT_FILE_MAX_BYTES:
            raise ValueError("TASK_CREDENTIAL_INVALID")

        temporary_fd = -1
        temporary_name: Optional[str] = None
        temporary_lock_module: Any = None
        temporary_locked = False
        replaced = False
        try:
            temporary_fd, temporary_name = tempfile.mkstemp(
                prefix=".%s." % self.path.name,
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            if os.name != "nt":
                os.fchmod(temporary_fd, 0o600)
            info = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (
                    os.name != "nt"
                    and stat.S_IMODE(info.st_mode) != 0o600
                )
                or (
                    os.name != "nt"
                    and hasattr(os, "geteuid")
                    and info.st_uid != os.geteuid()
                )
            ):
                raise ValueError("TASK_CREDENTIAL_INVALID")

            view = memoryview(encoded)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(temporary_fd)
            temporary_lock_module = self._lock_descriptor(
                temporary_fd
            )
            temporary_locked = True

            # Keep the last-good checkpoint and its lock until the complete,
            # fsynced replacement is also locked and ready for one atomic
            # same-directory swap.
            self._require_identity()
            os.replace(temporary_name, str(self.path))
            replaced = True

            if os.name != "nt":
                directory_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    directory_flags |= os.O_DIRECTORY
                if hasattr(os, "O_CLOEXEC"):
                    directory_flags |= os.O_CLOEXEC
                directory_fd = os.open(
                    str(self.path.parent),
                    directory_flags,
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)

            new_info = os.fstat(temporary_fd)
            path_info = os.stat(
                str(self.path),
                follow_symlinks=False,
            )
            new_identity = (new_info.st_dev, new_info.st_ino)
            if (
                not stat.S_ISREG(new_info.st_mode)
                or new_info.st_nlink != 1
                or (path_info.st_dev, path_info.st_ino)
                != new_identity
                or not stat.S_ISREG(path_info.st_mode)
                or path_info.st_nlink != 1
                or (
                    os.name != "nt"
                    and stat.S_IMODE(new_info.st_mode) != 0o600
                )
                or (
                    os.name != "nt"
                    and hasattr(os, "geteuid")
                    and new_info.st_uid != os.geteuid()
                )
            ):
                raise ValueError("TASK_CREDENTIAL_INVALID")

            old_fd = self.fd
            self.fd = temporary_fd
            temporary_fd = -1
            self.identity = new_identity
            self._lock_module = temporary_lock_module
            self.locked = True
            temporary_locked = False
            self.written = True
            os.close(old_fd)
        finally:
            if temporary_fd >= 0:
                if temporary_locked:
                    try:
                        self._unlock_descriptor(
                            temporary_fd,
                            temporary_lock_module,
                        )
                    except OSError:
                        pass
                os.close(temporary_fd)
            if not replaced and temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass

    def close(self) -> None:
        if not self.closed:
            try:
                self._release_exclusive_lock()
            finally:
                super().close()

    def close_or_remove_empty_reservation(self) -> None:
        if self.created_new and not self.written:
            self.remove_own_reservation()
        else:
            self.close()


def _reject_task_json_object_pairs(
    pairs: List[Tuple[str, Any]],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("TASK_CREDENTIAL_INVALID")
        result[key] = value
    return result


def _reject_task_json_constant(_value: str) -> None:
    raise ValueError("TASK_CREDENTIAL_INVALID")


def _read_task_json_file(path: str, *, require_private: bool) -> Dict[str, Any]:
    candidate = _validated_task_file_path(
        path,
        require_claims_root=require_private,
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOINHERIT"):
        flags |= os.O_NOINHERIT
    descriptor = os.open(str(candidate), flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > _TASK_FILE_MAX_BYTES
            or (require_private and before.st_nlink != 1)
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")
        if require_private and os.name != "nt":
            if before.st_mode & 0o077:
                raise ValueError("TASK_CREDENTIAL_INVALID")
            if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
                raise ValueError("TASK_CREDENTIAL_INVALID")
        content = bytearray()
        while len(content) <= _TASK_FILE_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _TASK_FILE_MAX_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        path_info = os.stat(str(candidate), follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (after.st_dev, after.st_ino)
            != (path_info.st_dev, path_info.st_ino)
            or not stat.S_ISREG(path_info.st_mode)
            or (require_private and path_info.st_nlink != 1)
            or len(content) > _TASK_FILE_MAX_BYTES
        ):
            raise ValueError("TASK_CREDENTIAL_INVALID")
    finally:
        os.close(descriptor)
    parse_failed = False
    value: Any = None
    try:
        value = json.loads(
            bytes(content).decode("utf-8"),
            object_pairs_hook=_reject_task_json_object_pairs,
            parse_constant=_reject_task_json_constant,
        )
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        parse_failed = True
    if parse_failed:
        content.clear()
        value = None
        raise ValueError("TASK_CREDENTIAL_INVALID")
    if type(value) is not dict:
        content.clear()
        value = None
        raise ValueError("TASK_CREDENTIAL_INVALID")
    return value


class _ChallengeParserOutcome(Enum):
    """Fixed internal outcome; attacker-controlled exception text is excluded."""

    NOT_APPLICABLE = "not_applicable"
    PARSED = "parsed"
    NO_VALID_CHALLENGE = "no_valid_challenge"
    PARSE_FAILURE = "parse_failure"
    UNEXPECTED_ERROR = "unexpected_error"


_PAYMENT_CHALLENGE_HEADERS = frozenset({
    "payment-required",
    "x-payment-required",
    "x-402-payment-required",
})
_NON_PAYMENT_AUTH_SCHEMES = frozenset({
    "basic",
    "bearer",
    "digest",
    "negotiate",
})
_SETTLEMENT_BODY_MARKERS = frozenset({
    "challenge",
    "accepts",
    "accepted_payments",
    "x402Version",
    "paymentRequirements",
    "resource",
})

def _requests_to_httpx_response(req_res: requests.Response, method: str = "GET") -> httpx.Response:
    # Body access is part of the response adapter boundary.  If it fails, let
    # the caller report ``response_adapter`` rather than silently parsing an
    # invented empty body.
    content = req_res.content or b""

    unsafe_headers = {
        "content-encoding",
        "transfer-encoding",
        "content-length",
    }

    safe_headers = {
        k: v
        for k, v in req_res.headers.items()
        if k.lower() not in unsafe_headers
    }

    return httpx.Response(
        status_code=req_res.status_code,
        headers=safe_headers,
        content=content,
        request=httpx.Request(method.upper(), req_res.url)
    )

def _settlement_rail_from_scheme(scheme: str, parsed=None) -> Optional[str]:
    if type(scheme) is not str or not scheme or scheme.lower() == "unknown":
        return "unknown"
    if scheme in ["exact", "batch-settlement", "auth-capture"]:
        return "x402"
    if scheme == "Payment" and parsed:
        raw_method = getattr(parsed, "payment_method", None)
        method = raw_method.lower() if type(raw_method) is str else ""
        parameters = getattr(parsed, "parameters", {})
        parameters = parameters if type(parameters) is dict else {}
        if method == "lightning" or parameters.get("invoice"):
            return "MPP"
        if method in ["eip3009", "exact", "evm", "x402", "batch-settlement", "auth-capture"]:
            return "x402"
        return "unknown"
    if scheme in ["L402", "MPP", "Payment", "x402"]:
        return scheme
    return "unknown"

CHAIN_HINTS = {
    "1": "Ethereum",
    "137": "Polygon",
    "8453": "Base",
    "196": "X Layer",
    "11155111": "Ethereum Sepolia"
}

_PUBLIC_SCHEMES = frozenset(
    {"exact", "batch-settlement", "auth-capture", "L402", "MPP", "Payment", "x402"}
)
_PUBLIC_INTENTS = frozenset(
    {
        "charge", "session", "batch", "escrow", "upto", "payment_mandate",
        "checkout_mandate", "mandate", "agentic_checkout", "cart", "catalog",
        "delegated_payment", "unknown",
    }
)
_PUBLIC_NETWORKS = frozenset({
    "unknown", "lightning", "btc",
    "eip155:1", "eip155:137", "eip155:196", "eip155:8453",
    "eip155:11155111",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
})
_PUBLIC_ASSET_SYMBOLS = frozenset({
    "BTC", "ETH", "JPYC", "SAT", "SATS", "USDC", "USDG", "unknown",
})
_PUBLIC_EVM_ASSET_ADDRESSES = frozenset({
    "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
    "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29",
})
_PUBLIC_SVM_ASSET_ADDRESSES = frozenset({
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
})
_LIGHTNING_INVOICE_RE = re.compile(r"^(?:lnbc|lntb|lnbcrt)[0-9a-z]{20,}$", re.IGNORECASE)
_JWT_LIKE_RE = re.compile(
    r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
)
_HEX_PRIVATE_KEY_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_LONG_BASE58_SECRET_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{45,128}$")
_PUBLIC_SELECTION_REASONS = frozenset(
    {
        "unknown", "not_selected", "no_allowed_network_match",
        "expected_chain_id", "prefer_svm", "first_acceptable",
        "fallback_first_presented", "invalid_network",
        "outer_inner_mismatch", "invalid_atomic_amount",
        "unknown_token_contract", "single_option_provided",
        "canonical_paid_surface_v1", "missing_canonical_requirement",
        "locally_bound_known_lightning", "locally_bound_known_exact",
    }
)


def _contains_public_control(value: str) -> bool:
    return any(
        ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F
        for char in value
    )


def _looks_like_secret_material(value: str) -> bool:
    normalized = value.strip()
    lowered = normalized.lower()
    return (
        _contains_public_control(normalized)
        or _contains_inspect_secret_material(normalized)
        or _LIGHTNING_INVOICE_RE.fullmatch(normalized) is not None
        or _JWT_LIKE_RE.fullmatch(normalized) is not None
        or _HEX_PRIVATE_KEY_RE.fullmatch(normalized) is not None
        or _LONG_BASE58_SECRET_RE.fullmatch(normalized) is not None
        or "private key" in lowered
        or "macaroon" in lowered
        or "preimage" in lowered
        or "credential" in lowered
        or "signature" in lowered
        or "receipt_token" in lowered
        or "access_token" in lowered
        or "refresh_token" in lowered
        or re.search(r"\bsecret\b", lowered) is not None
        or lowered.startswith(("bearer ", "basic "))
        or "-----begin" in lowered
    )


def _public_scheme(value: any) -> str:
    if type(value) is str and value in _PUBLIC_SCHEMES:
        return value
    return "REDACTED"


def _public_network(value: any) -> Optional[str]:
    if not isinstance(value, str) or _looks_like_secret_material(value):
        return "REDACTED" if value is not None else None
    normalized = value.lower()
    if normalized in {"unknown", "lightning", "btc"}:
        return normalized
    return value if value in _PUBLIC_NETWORKS else "REDACTED"


def _public_asset(value: any) -> Optional[str]:
    if not isinstance(value, str) or _looks_like_secret_material(value):
        return "REDACTED" if value is not None else None
    if value in _PUBLIC_ASSET_SYMBOLS:
        return value
    if value.lower() in _PUBLIC_EVM_ASSET_ADDRESSES:
        return value.lower()
    if value in _PUBLIC_SVM_ASSET_ADDRESSES:
        return value
    return "REDACTED"


def _public_amount(value: any) -> Optional[str]:
    if value is None:
        return None
    candidate = str(value)
    if len(candidate) > 128 or _looks_like_secret_material(candidate):
        return "REDACTED"
    # Amounts are attacker-controlled scalar strings and can encode arbitrary
    # identifiers even when they are syntactically numeric.  Inspect reports
    # only the existence of an amount, not its raw value.
    return "REDACTED"


def _public_intent(value: any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        return "unknown"
    normalized = value.lower()
    return normalized if normalized in _PUBLIC_INTENTS else "unknown"


def _public_x402_pay_to(value: any, network: any) -> Optional[str]:
    del network
    if value is None:
        return None
    # Recipient addresses are caller-controlled scalar identifiers.  They are
    # never needed for Inspect classification or observation reporting.
    return "REDACTED"


def _public_settlement_method(value: any) -> Optional[str]:
    if value is None:
        return None
    return (
        value
        if type(value) is str and value in {"evm_eip3009", "unknown"}
        else "REDACTED"
    )


def _public_selection_reason(value: any) -> str:
    return (
        value
        if type(value) is str and value in _PUBLIC_SELECTION_REASONS
        else "unknown"
    )

def _determine_chain_info(network: str) -> Tuple[str, Optional[str]]:
    if not network or network.lower() == "unknown":
        return "unknown", None
    n_lower = network.lower()
    if n_lower.startswith("eip155:"):
        chain_id = n_lower.split(":")[1]
        hint = CHAIN_HINTS.get(chain_id)
        return "evm", hint
    if n_lower.startswith("solana:"):
        return "svm", "Solana"
    if n_lower in ["lightning", "btc"]:
        return "lightning", "Lightning Network"
    return "unknown", None

def _extract_settlement_options(parsed: Optional[any]) -> Tuple[List[SettlementOption], Optional[SettlementOption]]:
    if not parsed:
        return [], None

    options = []
    selected_option = None
    parameters = getattr(parsed, "parameters", {})
    parameters = parameters if type(parameters) is dict else {}
    raw_accepted = parameters.get("_raw_accepted")
    raw_accepted = raw_accepted if type(raw_accepted) is dict else None
    all_accepted = parameters.get("_all_accepted", [])
    all_accepted = all_accepted if type(all_accepted) is list else []
    reason_from_parser = _public_selection_reason(
        parameters.get("_selection_reason", "unknown")
    )

    if not all_accepted and parsed.scheme in ["L402", "MPP", "Payment"]:
        public_network = _public_network(parsed.network)
        cf, ch = _determine_chain_info(public_network or "unknown")
        rail = _settlement_rail_from_scheme(parsed.scheme, parsed) or parsed.scheme
        raw_pay_to = parameters.get("destination") or parameters.get("invoice")
        public_pay_to = (
            "REDACTED"
            if rail in {"L402", "MPP"}
            else _public_x402_pay_to(raw_pay_to, public_network)
        )
        opt = SettlementOption(
            rail=rail,
            scheme=_public_scheme(parsed.scheme),
            network=public_network,
            chain_family=cf,
            chain_name_hint=ch,
            asset=_public_asset(parsed.asset),
            amount=_public_amount(parsed.amount),
            pay_to=public_pay_to,
            source="www_authenticate",
            execution_support="supported_but_not_executed_in_inspect" if rail in ["L402", "MPP"] else "unknown",
            selected=True,
            selection_reason="single_option_provided"
        )
        return [opt], opt

    # The challenge body is untrusted. Bound work and ignore malformed entries
    # instead of letting a mixed-type ``accepts`` array escape as an exception.
    for idx, req in enumerate(all_accepted[:32]):
        if type(req) is not dict:
            continue
        net = _public_network(req.get("network", "unknown")) or "unknown"
        cf, ch = _determine_chain_info(net)
        sch = _public_scheme(req.get("scheme", "exact"))
        
        support = "unknown"
        settlement_model = None
        authorization_artifact = None
        finality_model = None
        requires_channel_state = None
        deferred_settlement = None

        if sch == "exact": 
            support = "observe_only"
        elif sch == "batch-settlement":
            support = "observe_only"
            settlement_model = "deferred_batch"
            authorization_artifact = "voucher"
            finality_model = "deferred_onchain"
            requires_channel_state = True
            deferred_settlement = True
        elif sch == "auth-capture":
            support = "observe_only"
            settlement_model = "auth_capture_deferred_refundable"
            authorization_artifact = "authorization_signature"
            finality_model = "capture_void_refund_reclaim_lifecycle"
            requires_channel_state = False
            deferred_settlement = True
        elif cf in ["evm", "svm", "lightning"]: 
            support = "supported_but_not_executed_in_inspect"
        else: 
            support = "unsupported"
            
        is_selected = False
        reason = "not_selected"
        
        if raw_accepted and req == raw_accepted:
            is_selected = True
            reason = reason_from_parser
        elif reason_from_parser == "no_allowed_network_match":
            reason = "no_allowed_network_match"

        raw_amt = _public_amount(
            req.get("amount") or req.get("maxAmountRequired")
        )
        asset_val = _public_asset(
            req.get("symbol") or req.get("asset") or req.get("token") or req.get("mint")
        )
        
        opt = SettlementOption(
            rail="x402",
            scheme=sch,
            network=net,
            chain_family=cf,
            chain_name_hint=ch,
            asset=asset_val,
            amount=raw_amt,
            amount_atomic=raw_amt,
            pay_to=_public_x402_pay_to(req.get("payTo"), net),
            source=f"accepts[{idx}]",
            # A requirement-derived digest is still an attacker-controlled
            # scalar and can be used as a dictionary-testable covert channel.
            # Inspect exposes only this fixed representation.
            raw_requirement_fingerprint="REDACTED",
            execution_support=support,
            selected=is_selected,
            selection_reason=reason,
            settlement_model=settlement_model,
            authorization_artifact=authorization_artifact,
            finality_model=finality_model,
            requires_channel_state=requires_channel_state,
            deferred_settlement=deferred_settlement
        )
        options.append(opt)
        if is_selected:
            selected_option = opt
        
    return options, selected_option


def _www_authenticate_schemes(value: str) -> Tuple[str, ...]:
    """Return auth challenge schemes without reading quoted auth params."""
    masked = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            masked.append(" ")
        elif char == "\\" and quoted:
            escaped = True
            masked.append(" ")
        elif char == '"':
            quoted = not quoted
            masked.append(" ")
        elif quoted:
            masked.append(" ")
        else:
            masked.append(char)

    unquoted = "".join(masked)
    schemes = []
    for match in re.finditer(
        r"(?:^|,)\s*([!#$%&'*+\-.^_`|~0-9A-Za-z]+)",
        unquoted,
    ):
        cursor = match.end(1)
        while cursor < len(unquoted) and unquoted[cursor].isspace():
            cursor += 1
        if cursor < len(unquoted) and unquoted[cursor] == "=":
            continue
        schemes.append(match.group(1).lower())
    return tuple(schemes)


def _has_payment_or_settlement_marker(
    response: httpx.Response,
    commerce_info,
) -> bool:
    """Detect marker presence only when the parser reported true absence.

    A successfully parsed challenge remains governed by the existing parser.
    This predicate prevents an ignored or malformed marker from borrowing a
    successful AP2/ACP/OKX commerce classification.
    """
    headers = {
        str(name).lower(): str(value)
        for name, value in response.headers.items()
    }
    if any(name in headers for name in _PAYMENT_CHALLENGE_HEADERS):
        return True

    auth_value = headers.get("www-authenticate")
    if auth_value is not None:
        auth_schemes = _www_authenticate_schemes(auth_value)
        if not auth_schemes:
            return True
        if any(
            scheme not in _NON_PAYMENT_AUTH_SCHEMES
            for scheme in auth_schemes
        ):
            return True

    try:
        payload = response.json()
    except Exception:
        return False
    if type(payload) is not dict:
        return False
    if any(field in payload for field in _SETTLEMENT_BODY_MARKERS):
        return True
    marker_fields = [
        field for field in ("payment", "settlement") if field in payload
    ]
    if marker_fields:
        if (
            len(marker_fields) != 1
            or type(commerce_info) is not dict
            or commerce_info.get("commerce_protocol") != "okx_app"
        ):
            return True
        marker = payload[marker_fields[0]]
        if type(marker) is not dict or not marker:
            return True
        method = marker.get("method")
        network = marker.get("network")
        asset = marker.get("asset")
        if (
            type(method) is not str
            or method.lower() != "eip3009"
            or type(network) is not str
            or network.lower() not in {
                "196", "eip155:196", "xlayer", "x-layer",
            }
            or type(asset) is not str
            or asset.upper() != "USDG"
        ):
            return True
        if "amount" in marker:
            amount = marker["amount"]
            if isinstance(amount, bool) or not isinstance(
                amount, (str, int, float)
            ):
                return True
            amount_text = str(amount)
            if len(amount_text) > 128:
                return True
            try:
                decimal_amount = Decimal(amount_text)
            except (InvalidOperation, ValueError):
                return True
            if not decimal_amount.is_finite() or decimal_amount <= 0:
                return True
    return False


def _parse_failure_result(
    *,
    outcome: _ChallengeParserOutcome,
    public_url: str,
    status_code: int,
    grant_signals: Optional[GrantSignalObservation] = None,
) -> InspectResult:
    """Build one fixed, redacted parser result from an internal outcome."""
    if outcome is _ChallengeParserOutcome.NO_VALID_CHALLENGE:
        failure_class = "no_valid_challenge"
        diagnostic_class = "unsupported_challenge_shape"
        ok = True
        recommended_action = "reject_invalid"
    elif outcome is _ChallengeParserOutcome.PARSE_FAILURE:
        failure_class = "parse_failure"
        diagnostic_class = "invalid_payment_auth_request"
        ok = True
        recommended_action = "reject_invalid"
    else:
        failure_class = "unexpected_error"
        diagnostic_class = "x402_parse_error"
        ok = False
        recommended_action = "stop_safely"

    public_grant_signals = grant_signals or GrantSignalObservation()
    return InspectResult(
        ok=ok,
        url=public_url,
        http_status=status_code,
        error_stage="parse",
        failure_reason=failure_class,
        diagnostic_class=diagnostic_class,
        failure_class=failure_class,
        recommended_action=recommended_action,
        reason="Failed to parse challenge safely.",
        will_execute_payment=False,
        ln_church_observatory=ObservatoryMetadata(),
        grant_signal_detected=public_grant_signals.detected,
        grant_signals=public_grant_signals,
    )

def inspect_url(url: str, method: str = "GET", timeout: int = 10) -> InspectResult:
    try:
        res = _inspect_request(url, method=method, timeout=timeout)
    except InspectTransportError as exc:
        return InspectResult(
            ok=False,
            # Transport state, including redirect destinations, never defines
            # the public target identity.  Recompute it from the caller's
            # initial URL even if an internal exception carries another URL.
            url=redact_inspect_public_url(url),
            error_stage=exc.stage,
            failure_class=exc.code,
            failure_reason=exc.code,
            recommended_action="stop_safely",
            reason="Inspect request rejected by the fixed safety policy.",
            will_execute_payment=False
        )
    except Exception:
        return InspectResult(
            ok=False,
            url=redact_inspect_public_url(url),
            error_stage="transport",
            failure_class="network_error",
            failure_reason="network_error",
            recommended_action="stop_safely",
            reason="Inspect transport failed safely.",
            will_execute_payment=False,
        )

    # The public identity is always the canonical origin of the caller's
    # initial target.  A redirect destination is transport-only state: a
    # peer-controlled final authority must never replace the requested target
    # in CLI, MCP, or Observation output.
    public_url = redact_inspect_public_url(url)

    try:
        httpx_res = _requests_to_httpx_response(res, method)
    except Exception:
        challenge_status_observed = res.status_code in (401, 402, 403)
        return InspectResult(
            ok=challenge_status_observed,
            url=public_url,
            http_status=res.status_code,
            error_stage="response_adapter",
            failure_class="requests_to_httpx_conversion_failed",
            diagnostic_class="response_decoding_error",
            failure_reason="response_adapter_failed",
            recommended_action="stop_safely",
            reason="Failed to adapt the HTTP response safely.",
            will_execute_payment=False
        )

    parsed = None
    parser_outcome = _ChallengeParserOutcome.NOT_APPLICABLE
    if res.status_code in (402, 401, 403):
        try:
            parsed = parse_challenge_from_response(httpx_res)
            if getattr(parsed, "_inspect_semantically_valid", None) is not True:
                raise PaymentChallengeError("Malformed payment challenge.")
            parser_outcome = _ChallengeParserOutcome.PARSED
        except NoValidPaymentChallengeError:
            parser_outcome = _ChallengeParserOutcome.NO_VALID_CHALLENGE
        except PaymentChallengeError:
            parser_outcome = _ChallengeParserOutcome.PARSE_FAILURE
        except Exception:
            parser_outcome = _ChallengeParserOutcome.UNEXPECTED_ERROR

        if (
            parser_outcome is _ChallengeParserOutcome.PARSED
            and parsed is None
        ):
            parser_outcome = _ChallengeParserOutcome.UNEXPECTED_ERROR

        if parser_outcome in {
            _ChallengeParserOutcome.PARSE_FAILURE,
            _ChallengeParserOutcome.UNEXPECTED_ERROR,
        }:
            return _parse_failure_result(
                outcome=parser_outcome,
                public_url=public_url,
                status_code=res.status_code,
            )

    settlement_opts = []
    selected_opt = None
    try:
        if parsed:
            settlement_opts, selected_opt = _extract_settlement_options(parsed)
        commerce_info = detect_commerce_surface(httpx_res)
    except Exception:
        return InspectResult(
            ok=res.status_code in (401, 402, 403),
            url=public_url,
            http_status=res.status_code,
            error_stage="parse",
            failure_class="classification_failure",
            failure_reason="classification_failure",
            diagnostic_class="unsupported_challenge_shape",
            recommended_action="stop_safely",
            reason="Failed to classify the response safely.",
            will_execute_payment=False,
        )

    if (
        parser_outcome is _ChallengeParserOutcome.NO_VALID_CHALLENGE
        and _has_payment_or_settlement_marker(httpx_res, commerce_info)
    ):
        return _parse_failure_result(
            outcome=_ChallengeParserOutcome.PARSE_FAILURE,
            public_url=public_url,
            status_code=res.status_code,
        )

    try:
        grant_signals = detect_grant_signals(httpx_res)
    except Exception:
        grant_signals = GrantSignalObservation()

    if commerce_info:
        c_protocol = commerce_info.get("commerce_protocol")
        c_intent = _public_intent(commerce_info.get("commerce_intent"))
        
        scheme = _public_scheme(
            getattr(parsed, "scheme", "unknown") if parsed else "unknown"
        )
        if scheme == "REDACTED":
            scheme = "unknown"
        s_rail = _settlement_rail_from_scheme(scheme, parsed)
        
        surfaces_detected = []
        settlement_rails_detected = []
        rails_detected = [] 

        if c_protocol == "ap2": surfaces_detected.append("AP2")
        elif c_protocol == "acp": surfaces_detected.append("ACP")
        elif c_protocol == "okx_app":
            surfaces_detected.append("OKX_APP")
            rails_detected.append("APP")

        if scheme == "Payment":
            rails_detected.append("Payment") 
            if s_rail and s_rail not in ["Payment", "unknown"]:
                settlement_rails_detected.append(s_rail)
                rails_detected.append(s_rail)
        elif s_rail and s_rail != "unknown":
            settlement_rails_detected.append(s_rail)
            rails_detected.append(s_rail)

        action = "observe_only"
        unsupported_reason = None
        operator_approval_reason = None
        
        has_payment_headers = any(h.lower() in ["www-authenticate", "payment-required", "x-payment-required", "x-402-payment-required"] for h in httpx_res.headers.keys())
        is_malformed_hint = False
        
        if parsed and has_payment_headers and scheme == "unknown":
            is_malformed_hint = True
        elif scheme != "unknown" and s_rail not in ["x402", "L402", "MPP", "Payment"]:
            is_malformed_hint = True

        if is_malformed_hint:
            action = "stop_safely"
            unsupported_reason = "Malformed or unsupported settlement hint co-existing with commerce surface."
            operator_approval_reason = "malformed_or_unsupported_settlement_hint"
            reason = "Agent Commerce surface detected, but co-existing settlement hint is malformed or unsupported."
        elif not selected_opt and settlement_opts and parsed and parsed.parameters.get("_selection_reason") == "no_allowed_network_match":
            action = "stop_safely"
            unsupported_reason = "Settlement options are available, but none match the local allowed_networks policy."
            operator_approval_reason = "allowed_network_mismatch"
            reason = unsupported_reason
        else:
            operator_approval_reason = "commerce_surface_with_settlement_rail" if settlement_rails_detected else "commerce_surface_detected"
            if c_protocol in ["ap2", "acp"]:
                action = "observe_only"
                reason = commerce_info.get("reason", "Agent Commerce surface detected.")
                if settlement_rails_detected:
                    reason += " (Concrete HTTP 402 settlement challenge also detected, but payment is not executed by default for AP2/ACP)."
            else:
                reason = "Agent Commerce surface detected."
                if c_intent in ["session", "escrow", "upto"]:
                    action = "stop_safely"
                    reason = f"High-intent commerce flow ({c_intent}) observed but not executed by default."
                else:
                    action = "observe_only"

        try:
            guidance = build_commerce_guidance(
                c_protocol,
                commerce_info.get("raw_detected_fields", {}),
            )
        except Exception:
            return InspectResult(
                ok=res.status_code in (401, 402, 403),
                url=public_url,
                http_status=res.status_code,
                error_stage="parse",
                failure_class="classification_failure",
                failure_reason="classification_failure",
                diagnostic_class="unsupported_challenge_shape",
                recommended_action="stop_safely",
                reason="Failed to classify the response safely.",
                will_execute_payment=False,
            )

        if not settlement_opts:
            if "missing_information" not in guidance:
                guidance["missing_information"] = []
            guidance["missing_information"].extend([
                "settlement_rail_not_declared",
                "network_not_declared",
                "asset_not_declared",
                "post_payment_artifact_unknown"
            ])
            guidance["missing_information"] = list(dict.fromkeys(guidance["missing_information"]))

        return InspectResult(
            ok=True,
            url=public_url,
            http_status=res.status_code,
            rails_detected=rails_detected,
            surfaces_detected=surfaces_detected,
            settlement_rails_detected=settlement_rails_detected,
            surface_type=commerce_info.get("surface_type"),
            detection_confidence=commerce_info.get("confidence"),
            detection_reason=commerce_info.get("reason"),
            unsupported_reason=unsupported_reason,
            error_stage="parse" if is_malformed_hint else None,
            failure_class=(
                "unsupported_challenge_shape"
                if is_malformed_hint else None
            ),
            failure_reason=(
                "unsupported_challenge_shape"
                if is_malformed_hint else None
            ),
            recommended_action=action,
            reason=reason,
            will_execute_payment=False,
            diagnostic_class="commerce_surface_detected",
            commerce_protocol=c_protocol,
            commerce_intent=c_intent,
            commerce_transport=commerce_info.get("commerce_transport", "http"),
            authorization_artifact=commerce_info.get("authorization_artifact"),
            settlement_rail=s_rail if s_rail != "unknown" else None,
            settlement_method=_public_settlement_method(
                commerce_info.get("settlement_method")
            ),
            network=_public_network(commerce_info.get("network")),
            broker_required=commerce_info.get("broker_required"),
            classification_confidence=commerce_info.get("confidence"),
            app_protocol=c_protocol,
            app_intent=c_intent,
            app_transport=commerce_info.get("commerce_transport", "http"),
            handoff_mode=guidance.get("handoff_mode"),
            approval_required=guidance.get("approval_required"),
            ask_site_for=guidance.get("ask_site_for", []),
            do_not=guidance.get("do_not", []),
            required_evidence=guidance.get("required_evidence", []),
            missing_information=guidance.get("missing_information", []),
            operator_approval_reason=operator_approval_reason,
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    if res.status_code < 400 and res.status_code != 402:
        return InspectResult(
            ok=True,
            url=public_url,
            http_status=res.status_code,
            recommended_action="no_payment_required",
            reason="No HTTP 402 payment challenge detected.",
            will_execute_payment=False,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    if res.status_code in (402, 401, 403):
        if parser_outcome is _ChallengeParserOutcome.NO_VALID_CHALLENGE:
            return _parse_failure_result(
                outcome=parser_outcome,
                public_url=public_url,
                status_code=res.status_code,
                grant_signals=grant_signals,
            )

        scheme = _public_scheme(getattr(parsed, "scheme", "unknown"))
        if scheme == "REDACTED":
            scheme = "unknown"
        s_rail = _settlement_rail_from_scheme(scheme, parsed)
        
        rails = []
        if scheme == "Payment":
            rails.append("Payment")
            if s_rail and s_rail not in ["Payment", "unknown"]:
                rails.append(s_rail)
        elif s_rail and s_rail != "unknown":
            rails.append(s_rail)
        else:
            if scheme and scheme != "unknown":
                rails.append(scheme)
        
        intent = _public_intent(getattr(parsed, "payment_intent", None))
        shape = getattr(parsed, "draft_shape", None)
        source = getattr(parsed, "source", None)

        executable_rail = (
            scheme in {"L402", "MPP", "x402"}
            or (scheme == "Payment" and s_rail in {"L402", "MPP", "x402"})
        )
        action = "pay_and_verify" if executable_rail else "stop_safely"
        reason = (
            "Payment challenge detected. Inspect-only mode does not execute payments."
            if executable_rail
            else "Unsupported payment challenge shape was rejected safely."
        )
        next_cmd = None  
        diagnostic_class = None if executable_rail else "unsupported_challenge_shape"
        failure_class = None if executable_rail else "unsupported_challenge_shape"

        if not selected_opt and settlement_opts and parsed and parsed.parameters.get("_selection_reason") == "no_allowed_network_match":
            action = "stop_safely"
            diagnostic_class = "allowed_network_mismatch"
            reason = "Settlement options are available, but none match the local allowed_networks policy."
        elif intent == "session":
            action = "stop_safely"
            reason = "MPP session execution is observed but not executed by default."
            next_cmd = None
        elif scheme == "exact":
            action = "observe_only"
            diagnostic_class = "post_settlement_proof_required"
            failure_class = None
            reason = "This endpoint exposes an x402 exact challenge but validates only post-settlement evidence. The SDK-generated unbroadcasted exact payload will be rejected unless a submitted tx hash/signature is provided."
            next_cmd = None
        elif scheme == "batch-settlement":
            action = "observe_only"
            diagnostic_class = "deferred_batch_settlement_observed"
            failure_class = None
            reason = "x402 batch-settlement challenge detected. Request-time voucher / authorization artifact is not final settlement proof. Native execution is not implemented. Inspect-only mode will not sign vouchers or deposit funds."
            next_cmd = None
        elif scheme == "auth-capture":
            action = "observe_only"
            diagnostic_class = "deferred_auth_capture_observed"
            failure_class = None
            reason = "x402 auth-capture challenge detected. Authorization signature is not final settlement proof. Native execution is not implemented. Inspect-only mode will not sign, capture, void, refund, or reclaim."
            next_cmd = None
        elif shape in ["payment-auth-draft-partial", "payment-auth-draft-invalid-request"]:
            action = "reject_invalid"
            diagnostic_class = "invalid_payment_auth_request"
            reason = "Challenge shape is incomplete or invalid."
            next_cmd = None
        elif scheme == "Payment" and s_rail == "unknown":
            action = "stop_safely"
            diagnostic_class = "unsupported_challenge_shape"
            failure_class = "unsupported_challenge_shape"
            reason = "Payment scheme detected but payment method is unknown. The challenge was rejected safely."

        return InspectResult(
            ok=True,
            url=public_url,
            http_status=res.status_code,
            rails_detected=rails,
            settlement_rails_detected=rails, 
            challenge_source=source.value if source else None,
            payment_intent=intent,
            draft_shape=shape,
            recommended_action=action,
            reason=reason,
            next_command=next_cmd,
            will_execute_payment=False,
            diagnostic_class=diagnostic_class,
            error_stage="parse" if failure_class else None,
            failure_class=failure_class,
            failure_reason=failure_class,
            settlement_options=settlement_opts,
            selected_settlement_option=selected_opt,
            ln_church_observatory=ObservatoryMetadata(),
            grant_signal_detected=grant_signals.detected,
            grant_signals=grant_signals
        )

    return InspectResult(
        ok=False,
        url=public_url,
        http_status=res.status_code,
        error_stage="parse",
        failure_class="unexpected_http_status",
        failure_reason="unexpected_http_status",
        recommended_action="stop_safely",
        reason="Unexpected HTTP status during inspection.",
        will_execute_payment=False,
        grant_signal_detected=grant_signals.detected,
        grant_signals=grant_signals
    )

def main():
    _reject_task_secret_cli_arguments(_task_sys.argv[1:])
    parser = _TaskArgumentParser(description="ln-church-agent CLI - Agentic Payment Runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Existing `inspect`
    inspect_parser = subparsers.add_parser("inspect", help="Inspect an HTTP 402 endpoint without paying")
    inspect_parser.add_argument("url", type=str, help="Target URL")
    inspect_parser.add_argument("--method", type=str, default="GET", help="HTTP method (default: GET)")
    inspect_parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    inspect_parser.add_argument("--json", action="store_true", help="Output result as JSON")
    
    # 2. Existing `grant`
    grant_parser = subparsers.add_parser("grant", help="Manage and inspect grant tokens")
    grant_subparsers = grant_parser.add_subparsers(dest="grant_command", required=True)
    
    grant_inspect_parser = grant_subparsers.add_parser("inspect", help="Inspect a grant token locally without sending it")
    grant_inspect_parser.add_argument("--token", type=str, required=True, help="JWS Grant Token")
    grant_inspect_parser.add_argument("--agent-id", type=str, required=True, help="Expected Agent ID")
    grant_inspect_parser.add_argument("--route", type=str, default="/api/agent/omikuji", help="Target route")
    grant_inspect_parser.add_argument("--method", type=str, default="POST", help="Target HTTP method")
    grant_inspect_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="Target base URL")

    # Public, wallet-keyless Agent Task lifecycle. The official origin is fixed;
    # no task command accepts a custom origin or a plaintext token argument.
    task_parser = subparsers.add_parser(
        "task", help="Discover and complete public Agent Tasks"
    )
    task_subparsers = task_parser.add_subparsers(
        dest="task_command", required=True
    )
    task_list_parser = task_subparsers.add_parser("list", help="List Tasks")
    task_list_parser.add_argument(
        "--status",
        choices=["OPEN"],
        default="OPEN",
    )
    task_list_parser.add_argument("--limit", type=int, default=20)
    task_list_parser.add_argument("--cursor", type=str)
    task_list_parser.add_argument("--json", action="store_true")

    task_get_parser = task_subparsers.add_parser("get", help="Get Task detail")
    task_get_parser.add_argument("task_id", type=str)
    task_get_parser.add_argument("--limit", type=int, default=20)
    task_get_parser.add_argument("--cursor", type=str)
    task_get_parser.add_argument("--json", action="store_true")

    task_claim_parser = task_subparsers.add_parser(
        "claim", help="Claim one Task"
    )
    task_claim_parser.add_argument("task_id", type=str)
    task_claim_parser.add_argument("--agent-id", required=True)
    task_claim_parser.add_argument("--reward-address", required=True)
    task_claim_parser.add_argument("--credential-file", required=True)
    task_claim_parser.add_argument("--json", action="store_true")

    task_submit_parser = task_subparsers.add_parser(
        "submit", help="Submit a public-safe domain Observation"
    )
    task_submit_parser.add_argument("task_id", type=str)
    task_submit_parser.add_argument("--credential-file", required=True)
    task_submit_parser.add_argument("--file", required=True)
    task_submit_parser.add_argument("--json", action="store_true")

    task_submit_complete_parser = task_subparsers.add_parser(
        "submit-complete",
        help="Register an Observation and report Completion in one operation",
    )
    task_submit_complete_parser.add_argument("task_id", type=str)
    task_submit_complete_parser.add_argument(
        "--credential-file", required=True
    )
    task_submit_complete_parser.add_argument("--file", required=True)
    task_submit_complete_parser.add_argument(
        "--checkpoint-file", required=True
    )
    task_submit_complete_parser.add_argument("--json", action="store_true")

    task_complete_parser = task_subparsers.add_parser(
        "complete", help="Report Task completion"
    )
    task_complete_parser.add_argument("task_id", type=str)
    task_complete_parser.add_argument("--credential-file", required=True)
    task_complete_parser.add_argument("--submission-id", required=True)
    task_complete_parser.add_argument("--observation-id", required=True)
    task_complete_parser.add_argument("--json", action="store_true")

    task_status_parser = task_subparsers.add_parser(
        "status", help="Get Task and reward status"
    )
    task_status_parser.add_argument("task_id", type=str)
    task_status_parser.add_argument("--credential-file", required=True)
    task_status_parser.add_argument("--submission-id", required=True)
    task_status_parser.add_argument("--observation-id", required=True)
    task_status_parser.add_argument("--json", action="store_true")

    task_wait_parser = task_subparsers.add_parser(
        "reward-wait", help="Wait for a terminal reward state"
    )
    task_wait_parser.add_argument("task_id", type=str)
    task_wait_parser.add_argument("--credential-file", required=True)
    task_wait_parser.add_argument("--submission-id", required=True)
    task_wait_parser.add_argument("--observation-id", required=True)
    task_wait_parser.add_argument("--timeout-seconds", type=float, default=300)
    task_wait_parser.add_argument("--max-attempts", type=int, default=10)
    task_wait_parser.add_argument("--json", action="store_true")

    # 💡 3. [NEW] Paid Registration & Read Models (`observe-domain`)
    obs_domain_parser = subparsers.add_parser("observe-domain", help="Manage paid domain observation slots")
    obs_domain_sub = obs_domain_parser.add_subparsers(dest="obs_cmd", required=True)
    
    register_parser = obs_domain_sub.add_parser("register", help="Register a domain (Paid Action)")
    register_parser.add_argument("domain", type=str, help="Public domain to observe")
    register_parser.add_argument("--pay", action="store_true", help="Acknowledge this is a paid action (approx 1 USDC)")
    register_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    register_parser.add_argument("--private-key", type=str, help="Agent EVM Private Key (or set via ENV)")
    register_parser.add_argument("--idempotency-key", type=str, help="Optional idempotency key to prevent double charges")
    register_parser.add_argument("--json", action="store_true", help="Output as JSON")

    status_parser = obs_domain_sub.add_parser("status", help="Get request status")
    status_parser.add_argument("request_id", type=str, help="The Observation Request ID")
    status_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    status_parser.add_argument("--json", action="store_true")

    rm_parser = obs_domain_sub.add_parser("read-model", help="Get domain read model")
    rm_parser.add_argument("domain", type=str, help="The target domain")
    rm_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    rm_parser.add_argument("--json", action="store_true")

    # 💡 4. [NEW] Internal Observatory (default_worker) (`observatory`)
    observatory_parser = subparsers.add_parser("observatory", help="Internal Observer API")
    obs_sub = observatory_parser.add_subparsers(dest="observatory_cmd", required=True)
    
    targets_parser = obs_sub.add_parser("targets")
    targets_sub = targets_parser.add_subparsers(dest="targets_cmd", required=True)
    claim_parser = targets_sub.add_parser("claim", help="Claim targets for observation")
    claim_parser.add_argument("--observer", type=str, default="default_worker")
    claim_parser.add_argument("--limit", type=int, default=5)
    claim_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    claim_parser.add_argument("--internal-secret", type=str, help="Or use LN_CHURCH_INTERNAL_SECRET env")
    claim_parser.add_argument("--json", action="store_true")

    results_parser = obs_sub.add_parser("results")
    results_sub = results_parser.add_subparsers(dest="results_cmd", required=True)
    submit_parser = results_sub.add_parser("submit", help="Submit observation result")
    submit_parser.add_argument("file", type=str, help="Path to result JSON file")
    submit_parser.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com", help="API Base URL")
    submit_parser.add_argument("--internal-secret", type=str, help="Or use LN_CHURCH_INTERNAL_SECRET env")
    submit_parser.add_argument("--json", action="store_true")

    # 💡1.15.0
    sponsor_parser = obs_domain_sub.add_parser("sponsor", help="Manage domain sponsor verification")
    sponsor_sub = sponsor_parser.add_subparsers(dest="sponsor_cmd", required=True)
    
    chal_cmd = sponsor_sub.add_parser("challenge", help="Issue a sponsor challenge")
    chal_cmd.add_argument("request_id", type=str, help="Observation Request ID")
    chal_cmd.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    chal_cmd.add_argument("--result-handle", type=str, help="Proof handle (or LN_CHURCH_RESULT_HANDLE env)")
    chal_cmd.add_argument("--request-hash", type=str, help="Proof hash (or LN_CHURCH_REQUEST_HASH env)")
    chal_cmd.add_argument("--internal-secret", type=str, help="Or use LN_CHURCH_INTERNAL_SECRET env")
    chal_cmd.add_argument("--json", action="store_true", help="Output JSON response (excludes headers)")
    chal_cmd.add_argument("--output-file", type=str, help="Save challenge document safely to a file")
    chal_cmd.add_argument("--print-document", action="store_true", help="Print challenge document JSON to stdout")
    chal_cmd.add_argument("--proof-file", type=str, help="Load result-handle/request-hash from proof file")

    ver_cmd = sponsor_sub.add_parser("verify", help="Verify the sponsor challenge")
    ver_cmd.add_argument("request_id", type=str, help="Observation Request ID")
    ver_cmd.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    ver_cmd.add_argument("--result-handle", type=str)
    ver_cmd.add_argument("--request-hash", type=str)
    ver_cmd.add_argument("--internal-secret", type=str)
    ver_cmd.add_argument("--json", action="store_true")
    ver_cmd.add_argument("--proof-file", type=str, help="Load result-handle/request-hash from proof file")

    track_parser = obs_domain_sub.add_parser("track", help="Manage Verified Domain Tracks")
    track_sub = track_parser.add_subparsers(dest="track_cmd", required=True)
    
    trk_reg = track_sub.add_parser("register", help="Register a Verified Domain Track (Paid Action)")
    trk_reg.add_argument("domain", type=str)
    trk_reg.add_argument("--plan", type=str, default="verified_domain_track_lite")
    trk_reg.add_argument("--idempotency-key", type=str)
    trk_reg.add_argument("--proof-file", type=str)
    trk_reg.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    trk_reg.add_argument("--json", action="store_true")
    
    trk_reg.add_argument("--pay", action="store_true", help="Acknowledge this is a paid action (19 USDC)")
    trk_reg.add_argument("--max-spend-usd", type=float, default=25.0, help="Max spend for this transaction (default: 25.0)")
    trk_reg.add_argument("--private-key", type=str, help="Agent EVM Private Key (or AGENT_PRIVATE_KEY)")
    trk_reg.add_argument("--include-proof", action="store_true", help="Include secret proof details in JSON output")
    
    trk_stat = track_sub.add_parser("status", help="Get Verified Domain Track Status")
    trk_stat.add_argument("request_id", type=str)
    trk_stat.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    trk_stat.add_argument("--json", action="store_true")

    trk_dom = track_sub.add_parser("domain", help="Get Domain Verified Track Read Model")
    trk_dom.add_argument("domain", type=str)
    trk_dom.add_argument("--base-url", type=str, default="https://kari.mayim-mayim.com")
    trk_dom.add_argument("--json", action="store_true")

    args = parser.parse_args()

    # --- CLI Execution Handlers ---

    if args.command == "inspect":
        result = inspect_url(args.url, args.method, args.timeout)
        if args.json:
            print(result.model_dump_json(exclude_none=True, indent=2))
        else:
            print(f"🔍 Inspection Result for {result.url}")
            print(f"  OK                 : {result.ok}")
            print(f"  HTTP Status        : {result.http_status}")
            print(f"  Action             : {result.recommended_action}")
            print(f"  Rails Detected     : {', '.join(result.rails_detected) if result.rails_detected else 'None'}")
            print(f"  Surfaces Detected  : {', '.join(result.surfaces_detected) if result.surfaces_detected else 'None'}")
            print(f"  Reason             : {result.reason}")
            
            if result.settlement_options:
                print(f"  Settlement Options : {len(result.settlement_options)} available")
                for i, opt in enumerate(result.settlement_options):
                    sel_mark = "*" if opt.selected else "-"
                    print(f"    {sel_mark} [{opt.chain_family}] {opt.network} - {opt.asset} (Scheme: {opt.scheme})")
                    
            if result.next_command:
                print(f"  Next Command       : {result.next_command}")
            if getattr(result, "diagnostic_class", None):
                print(f"  Diagnostic Class   : {result.diagnostic_class}")
            if not result.ok and result.failure_reason:
                print(f"  Failure            : {result.error_stage} -> {result.failure_reason}")

            if getattr(result, "grant_signal_detected", False):
                print(f"  Grant Signal       : detected (confidence: {result.grant_signals.confidence})")
                if result.grant_signals.signal_types:
                    print(f"  Grant Signal Type  : {', '.join(result.grant_signals.signal_types)}")

            print("\n---------------------------------------------------------")
            print("💡 Observation generated locally. This result was not submitted.")
            print("To contribute a redacted observation to the public corpus, use an explicit opt-in submission flow.")
            print("LN Church Observatory collects agent-readable evidence for HTTP 402 / x402 / L402 / MPP payment surfaces.")
            print("---------------------------------------------------------")

    elif args.command == "grant" and args.grant_command == "inspect":
        from .grants import diagnose_grant_token
        import json
        diag = diagnose_grant_token(args.token, agent_id=args.agent_id, base_url=args.base_url, route=args.route, method=args.method)
        res = {
            "usable": diag.usable,
            "failure_class": diag.failure_class,
            "access_path": diag.access_path,
            "authorization_artifact": diag.authorization_artifact,
            "settlement_rail": diag.settlement_rail,
            "scope": {
                "routes": diag.scope_routes,
                "methods": diag.scope_methods
            },
            "recommended_action": diag.recommended_action,
            "note": "Local diagnostics only. Server-side validation is authoritative."
        }
        if diag.reason:
            res["reason"] = diag.reason
        if diag.fallback_action:
            res["fallback_action"] = diag.fallback_action
        print(json.dumps(res, indent=2))

    elif args.command == "task":
        # Imports remain lazy so the existing inspect/payment CLI surface keeps
        # importing normally when optional integrations are absent.
        from .task_client import AgentTaskClient
        from .task_models import (
            TaskClaimCredential,
            TaskDomainObservationCheckpoint,
            TaskDomainObservationSubmission,
        )
        from .task_contract import (
            validate_agent_id,
            validate_reward_address,
            validate_task_id,
        )
        from .task_transport import TaskError

        def _print_task_reward(
            reward: Any,
            *,
            label: str,
            indent: str = "",
        ) -> None:
            print(
                "%s%s: %s atomic %s on %s (%s)"
                % (
                    indent,
                    label,
                    reward.amount_atomic,
                    reward.asset,
                    reward.network,
                    reward.asset_address,
                )
            )

        def _print_task_offer_snapshot(
            task: Any,
            *,
            indent: str = "",
        ) -> None:
            offer_fields = (
                ("Active executions", "active_execution_count"),
                ("Successful claims", "claim_count_total"),
                ("Rewarded executions", "rewarded_execution_count"),
                ("Paid total (atomic)", "reward_paid_total_minor"),
                ("Capacity total", "capacity_total"),
                ("Capacity remaining", "capacity_remaining"),
                (
                    "Maximum reward principal",
                    "maximum_reward_principal_atomic",
                ),
                ("Claimable", "claimable"),
            )
            for label, field in offer_fields:
                if hasattr(task, field):
                    suffix = ""
                    if field == "capacity_remaining":
                        suffix = " (read-time snapshot; not a Claim guarantee)"
                    print(
                        "%s%-24s: %s%s"
                        % (
                            indent,
                            label,
                            getattr(task, field),
                            suffix,
                        )
                    )
            if hasattr(task, "reward"):
                _print_task_reward(
                    task.reward,
                    label="Advertised reward (Hondo-provided)",
                    indent=indent,
                )
            if hasattr(task, "poc_terms"):
                terms = task.poc_terms
                print(
                    "%sCompletion 2xx      : %s"
                    % (indent, terms.completion_2xx_meaning)
                )
                print(
                    "%sPayout mode          : %s"
                    % (indent, terms.payout_mode)
                )
                for label, field in (
                    (
                        "Evaluation approval",
                        "completion_2xx_implies_evaluation_approval",
                    ),
                    (
                        "Payment completion",
                        "completion_2xx_implies_payment_completion",
                    ),
                    ("Payment SLA", "payment_completion_sla"),
                    ("Individual investigation", "individual_investigation"),
                    ("Manual resend", "manual_resend"),
                    ("Compensation", "compensation"),
                    ("Alternative payment", "alternative_payment"),
                    (
                        "Arbitrary non-payment",
                        "arbitrary_non_payment_authorized",
                    ),
                ):
                    print(
                        "%s%-24s: %s"
                        % (indent, label, getattr(terms, field))
                    )
                print(
                    "%sRequired surfaces    : %s"
                    % (
                        indent,
                        ", ".join(terms.required_public_surfaces),
                    )
                )

        def _print_execution_summaries(
            task: Any,
            *,
            indent: str = "",
        ) -> None:
            if not hasattr(task, "execution_summaries"):
                return
            summaries = task.execution_summaries
            print("%sExecution summaries: %d" % (indent, len(summaries)))
            for summary in summaries:
                print(
                    "%s  %s  %s  %s"
                    % (
                        indent,
                        summary.submission_id,
                        summary.task_status,
                        summary.reward_state,
                    )
                )
                print(
                    "%s    Observation: %s"
                    % (indent, summary.observation_id)
                )
                _print_task_reward(
                    summary,
                    label="Claim reward snapshot",
                    indent=indent + "    ",
                )
                for label, field in (
                    ("Evaluated", "evaluated_at"),
                    ("Reward tx", "reward_tx_hash"),
                    ("Rewarded", "rewarded_at"),
                    ("Failure code", "failure_code"),
                ):
                    print(
                        "%s    %-12s: %s"
                        % (indent, label, getattr(summary, field))
                    )
            print(
                "%sNext cursor        : %s"
                % (
                    indent,
                    getattr(task, "execution_summaries_next_cursor", None),
                )
            )

        def _print_task_result(value: Any, json_mode: bool) -> None:
            payload = _task_public_payload(value)
            if json_mode:
                print(
                    _task_json.dumps(
                        payload,
                        indent=2,
                        ensure_ascii=False,
                        allow_nan=False,
                    )
                )
                return
            if hasattr(value, "register_receipt"):
                register_receipt = value.register_receipt
                completion_receipt = getattr(
                    value, "completion_receipt", None
                )
                matched_status = getattr(value, "matched_status", None)
                print("Task ID             : %s" % register_receipt.task_id)
                print(
                    "Register receipt     : %s"
                    % register_receipt.status
                )
                if completion_receipt is not None:
                    print(
                        "Completion receipt   : %s"
                        % completion_receipt.status
                    )
                    print("Matched status       : not used")
                else:
                    print(
                        "Completion receipt   : not returned "
                        "(status reconciled)"
                    )
                    print(
                        "Matched task status   : %s"
                        % matched_status.task_status
                    )
                    print(
                        "Matched reward state  : %s"
                        % matched_status.reward_state
                    )
                return
            if hasattr(value, "task_id"):
                print("Task ID     : %s" % value.task_id)
            if hasattr(value, "status"):
                print("Status      : %s" % value.status)
            if hasattr(value, "task_status"):
                print("Task status : %s" % value.task_status)
            if hasattr(value, "reward_state"):
                print("Reward state: %s" % value.reward_state)
            if hasattr(value, "failure_code"):
                print("Failure code: %s" % value.failure_code)
            if hasattr(value, "evaluated_at"):
                print("Evaluated   : %s" % value.evaluated_at)
            if hasattr(value, "reward_tx_hash"):
                print("Reward tx   : %s" % value.reward_tx_hash)
            if hasattr(value, "rewarded_at"):
                print("Rewarded    : %s" % value.rewarded_at)
            if hasattr(value, "observation_id"):
                print("Observation : %s" % value.observation_id)
            _print_task_offer_snapshot(value)
            _print_execution_summaries(value)
            if (
                not hasattr(value, "reward")
                and all(
                    hasattr(value, field)
                    for field in (
                        "network",
                        "asset",
                        "asset_address",
                        "amount_atomic",
                    )
                )
            ):
                _print_task_reward(
                    value,
                    label="Claim reward",
                )

        client = None
        try:
            client = AgentTaskClient()
            if args.task_command == "list":
                result = client.list_tasks(
                    status=args.status,
                    limit=args.limit,
                    cursor=args.cursor,
                )
                if args.json:
                    _print_task_result(result, True)
                else:
                    print("Tasks: %d" % len(result.tasks))
                    for task in result.tasks:
                        print(
                            "  %s  %s  %s"
                            % (task.task_id, task.status, task.task_type)
                        )
                        _print_task_offer_snapshot(task, indent="    ")

            elif args.task_command == "get":
                _print_task_result(
                    client.get_task(
                        args.task_id,
                        limit=args.limit,
                        cursor=args.cursor,
                    ),
                    args.json,
                )

            elif args.task_command == "claim":
                try:
                    claim_task_id = validate_task_id(args.task_id)
                    claim_agent_id = validate_agent_id(args.agent_id)
                    claim_reward_address = validate_reward_address(
                        args.reward_address
                    )
                except (TypeError, ValueError):
                    _task_cli_error("invalid_request")
                try:
                    reservation = _TaskCredentialReservation(
                        args.credential_file
                    )
                except (OSError, ValueError):
                    _task_cli_error("TASK_CREDENTIAL_INVALID")

                try:
                    claim = client.claim_task(
                        claim_task_id,
                        agent_id=claim_agent_id,
                        reward_address=claim_reward_address,
                    )
                except TaskError as exc:
                    can_remove = (
                        getattr(exc, "request_bytes_sent", None) is False
                        or getattr(exc, "mutation_free", None) is True
                    )
                    try:
                        if can_remove:
                            reservation.remove_own_reservation()
                        else:
                            reservation.write_payload(
                                _task_tombstone(claim_task_id)
                            )
                            reservation.close()
                    except (OSError, ValueError):
                        if not can_remove:
                            try:
                                reservation.scrub_with_tombstone(
                                    _task_tombstone(claim_task_id)
                                )
                            except (OSError, TypeError, ValueError):
                                pass
                        reservation.close()
                        if can_remove:
                            _task_cli_error("TASK_CREDENTIAL_INVALID")
                    _task_cli_error(
                        getattr(exc, "code", None)
                        if can_remove
                        else "CLAIM_OUTCOME_UNKNOWN"
                    )
                except Exception:
                    try:
                        reservation.scrub_with_tombstone(
                            _task_tombstone(claim_task_id)
                        )
                    except (OSError, TypeError, ValueError):
                        pass
                    reservation.close()
                    _task_cli_error("CLAIM_OUTCOME_UNKNOWN")

                try:
                    if (
                        claim.task_id != claim_task_id
                        or claim.credential.task_id != claim_task_id
                        or claim.credential.agent_id != claim_agent_id
                        or claim.credential.api_origin != _TASK_FIXED_ORIGIN
                        or claim.credential.reward_address
                        != claim_reward_address
                    ):
                        raise ValueError("TASK_CREDENTIAL_INVALID")
                    reservation.write_payload(
                        _task_active_credential_payload(claim.credential)
                    )
                    reservation.close()
                except Exception:
                    try:
                        reservation.scrub_with_tombstone(
                            _task_tombstone(claim_task_id)
                        )
                    except (OSError, TypeError, ValueError):
                        pass
                    reservation.close()
                    _task_cli_error("TASK_CREDENTIAL_INVALID")

                if args.json:
                    public_claim = {
                        "schema_version": claim.schema_version,
                        "task_id": claim.task_id,
                        "task_type": claim.task_type,
                        "task_definition_version": (
                            claim.task_definition.task_definition_version
                        ),
                        "task_definition_digest": (
                            claim.task_definition.task_definition_digest
                        ),
                        "manifest_url": claim.task_definition.manifest_url,
                        "manifest_sha256": (
                            claim.task_definition.manifest_sha256
                        ),
                        "status": claim.status,
                        "lease_duration_seconds": (
                            claim.lease_duration_seconds
                        ),
                        "lease_expires_at": claim.lease_expires_at,
                        "reward_address": claim.reward_address,
                        "reward_address_control_verified": (
                            claim.reward_address_control_verified
                        ),
                        "reward": _task_public_payload(claim.reward),
                        "credential_file_written": True,
                    }
                    print(
                        _task_json.dumps(
                            public_claim,
                            indent=2,
                            ensure_ascii=False,
                            allow_nan=False,
                        )
                    )
                else:
                    print("Task claimed; credential file written securely.")
                    print("Task ID     : %s" % claim.task_id)
                    print("Lease expiry: %s" % claim.lease_expires_at)
                    _print_task_reward(
                        claim.reward,
                        label="Claim reward",
                    )

            elif args.task_command in {
                "submit",
                "submit-complete",
                "complete",
                "status",
                "reward-wait",
            }:
                try:
                    credential_payload = _read_task_json_file(
                        args.credential_file, require_private=True
                    )
                    credential = _task_credential_from_payload(
                        credential_payload,
                        TaskClaimCredential,
                    )
                    if credential.task_id != args.task_id:
                        raise ValueError("TASK_CREDENTIAL_INVALID")
                    if (
                        args.task_command
                        in {"submit", "submit-complete", "complete"}
                        and credential.is_expired()
                    ):
                        _task_cli_error("TASK_CREDENTIAL_EXPIRED")
                except SystemExit:
                    raise
                except (OSError, ValueError):
                    _task_cli_error("TASK_CREDENTIAL_INVALID")

                if args.task_command == "submit":
                    try:
                        submission_payload = _read_task_json_file(
                            args.file, require_private=False
                        )
                        submission = (
                            TaskDomainObservationSubmission.model_validate(
                                submission_payload
                            )
                        )
                    except (OSError, ValueError):
                        _task_cli_error("TASK_RESPONSE_INVALID")
                    try:
                        result = client.submit_domain_observation(
                            credential, submission
                        )
                    except TaskError as exc:
                        _task_cli_error(getattr(exc, "code", None))
                elif args.task_command == "submit-complete":
                    checkpoint_file = None
                    try:
                        checkpoint_file = _TaskCheckpointFile(
                            args.checkpoint_file
                        )
                        checkpoint_type = TaskDomainObservationCheckpoint
                        checkpoint = None
                        if not checkpoint_file.created_new:
                            checkpoint = checkpoint_type.model_validate(
                                checkpoint_file.read_payload(),
                                strict=True,
                            )
                            checkpoint = checkpoint._validated_snapshot()
                        try:
                            # Keep this as a raw bounded mapping.  On resume
                            # the client first restores the checkpoint's
                            # submission_id, then strictly validates the
                            # reconstructed submission so omission of the ID
                            # cannot generate a fresh identity.
                            submission_payload = _read_task_json_file(
                                args.file, require_private=False
                            )
                        except (OSError, ValueError):
                            _task_cli_error("TASK_RESPONSE_INVALID")

                        def persist_checkpoint(value: Any) -> None:
                            try:
                                if (
                                    type(value)
                                    is not checkpoint_type
                                ):
                                    raise ValueError
                                snapshot = value._validated_snapshot()
                                payload = snapshot.model_dump(
                                    mode="json",
                                    exclude_none=True,
                                )
                                if (
                                    type(payload) is not dict
                                    or _task_public_payload(payload) != payload
                                ):
                                    raise ValueError
                                checkpoint_file.write_payload(payload)
                            except Exception:
                                raise ValueError(
                                    "TASK_CREDENTIAL_INVALID"
                                ) from None

                        result = (
                            client.submit_and_complete_domain_observation(
                                credential,
                                submission_payload,
                                checkpoint=checkpoint,
                                checkpoint_sink=persist_checkpoint,
                            )
                        )
                    except TaskError as exc:
                        _task_cli_error(getattr(exc, "code", None))
                    except (OSError, TypeError, ValueError):
                        _task_cli_error("TASK_CREDENTIAL_INVALID")
                    finally:
                        if checkpoint_file is not None:
                            try:
                                (
                                    checkpoint_file
                                    .close_or_remove_empty_reservation()
                                )
                            except (OSError, ValueError):
                                try:
                                    checkpoint_file.close()
                                except OSError:
                                    pass
                elif args.task_command == "complete":
                    try:
                        result = client.complete_task(
                            credential,
                            submission_id=args.submission_id,
                            observation_id=args.observation_id,
                        )
                    except TaskError as exc:
                        _task_cli_error(getattr(exc, "code", None))
                elif args.task_command == "status":
                    result = client.get_reward_status(
                        args.task_id,
                        submission_id=args.submission_id,
                        observation_id=args.observation_id,
                        task_definition=credential.task_definition,
                        reward=credential.reward,
                    )
                else:
                    result = client.wait_for_reward(
                        args.task_id,
                        submission_id=args.submission_id,
                        observation_id=args.observation_id,
                        task_definition=credential.task_definition,
                        reward=credential.reward,
                        timeout_seconds=args.timeout_seconds,
                        max_attempts=args.max_attempts,
                    )
                _print_task_result(result, args.json)
        except SystemExit:
            raise
        except TaskError as exc:
            _task_cli_error(getattr(exc, "code", None))
        except Exception:
            _task_cli_error("TASK_RESPONSE_INVALID")
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass

    # 💡 [NEW] Paid Domain Observation Slot Management
    elif args.command == "observe-domain":
        from .client import LnChurchClient
        import os, json

        def _load_proof_file(proof_file: str):
            import json
            with open(proof_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            rh = data.get("result_handle")
            rhsh = data.get("request_hash")

            if not rh or not rhsh:
                raise ValueError("Proof file is missing result_handle or request_hash.")

            return rh, rhsh

        if args.obs_cmd == "register":
            pk = getattr(args, "private_key", None) or os.environ.get("AGENT_PRIVATE_KEY")
            if not pk:
                print("❌ Error: --private-key or AGENT_PRIVATE_KEY environment variable is required to register a domain.")
                return
            if not args.pay:
                print("❌ Safety Check Failed: This is a paid endpoint. Use '--pay' to explicitly acknowledge the payment action.")
                return
                
            client = LnChurchClient(private_key=pk)
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            try:
                res = client.register_domain_observation_slot(args.domain, idempotency_key=args.idempotency_key)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Slot Registered for {res.domain}")
                    print(f"  Request ID    : {res.request_id}")
                    print(f"  Requester Paid: {res.requester_paid}")
                    print(f"  Result Handle : {res.result_handle}")
                    print(f"  Read Model    : {res.public_read_model_url}")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.obs_cmd == "status":
            client = LnChurchClient(agent_id="cli_observer")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            try:
                res = client.get_domain_observation_request(args.request_id)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Status for {res.domain}:")
                    print(f"  Request ID : {res.request_id}")
                    print(f"  Status     : {res.status}")
                    print(f"  Observed   : {res.observation_count} times (Last: {res.last_observed_at or 'Never'})")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.obs_cmd == "read-model":
            client = LnChurchClient(agent_id="cli_observer")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            try:
                res = client.get_domain_observation_read_model(args.domain)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Read Model for {res.domain}:")
                    print(f"  Latest Observations : {len(res.latest_observations)}")
                    print(f"  Discovered Surfaces : {len(res.discovered_surfaces)}")
                    print(f"  Verdict / Score     : None (not_a_verdict=True)")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.obs_cmd == "sponsor":
            client = LnChurchClient(agent_id="cli_sponsor")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            rh = getattr(args, "result_handle", None)
            rhsh = getattr(args, "request_hash", None)
            secret = getattr(args, "internal_secret", None) or os.environ.get("LN_CHURCH_INTERNAL_SECRET")
            
            if hasattr(args, "proof_file") and args.proof_file and (not rh or not rhsh):
                f_rh, f_rhsh = _load_proof_file(args.proof_file)
                if not rh: rh = f_rh
                if not rhsh: rhsh = f_rhsh

            rh = rh or os.environ.get("LN_CHURCH_RESULT_HANDLE")
            rhsh = rhsh or os.environ.get("LN_CHURCH_REQUEST_HASH")

            if args.sponsor_cmd == "challenge":
                try:
                    res = client.create_domain_sponsor_challenge(
                        args.request_id, result_handle=rh, request_hash=rhsh, internal_secret=secret
                    )
                    
                    if args.output_file:
                        client.save_domain_sponsor_challenge_document(res, args.output_file)
                        if not args.json and not args.print_document:
                            print("✅ Challenge document saved.")
                            print(f"  File      : {args.output_file}")
                            print(f"  Publish   : {res.challenge_url}")
                            print(f"  Verify    : ln-church-agent observe-domain sponsor verify {res.request_id}")
                            
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    elif args.print_document:
                        print(json.dumps(res.challenge_document, indent=2, ensure_ascii=False))
                    elif not args.output_file:
                        print("✅ Domain sponsor challenge issued.")
                        print(f"  Request ID : {res.request_id}")
                        print(f"  Domain     : {res.domain}")
                        print(f"  Challenge  : {res.challenge_url}")
                        print(f"  Scope      : domain_control_not_legal_ownership\n")
                        print("Challenge document contains a public challenge_token.")
                        print("Use --output-file .well-known/ln-church-domain-sponsor.json to save it safely.")
                        
                except Exception as e:
                    print(f"❌ Failed: {e}")

            elif args.sponsor_cmd == "verify":
                try:
                    res = client.verify_domain_sponsor(
                        args.request_id, result_handle=rh, request_hash=rhsh, internal_secret=secret
                    )
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    else:
                        print("✅ Domain-control sponsor verified.")
                        print(f"  Request ID              : {res.request_id}")
                        print(f"  Domain                  : {res.domain}")
                        print(f"  Domain Control Verified : {res.domain_control_verified}")
                        print(f"  Scope                   : {res.verification_scope}")
                        print(f"  Legal Ownership Proof   : {res.not_legal_ownership_proof is not True}")
                        print(f"  Read Model              : {res.public_read_model_url}")
                except Exception as e:
                    print(f"❌ Failed: {e}")

        elif args.obs_cmd == "track":
            client = LnChurchClient(agent_id="cli_observer")
            if hasattr(args, "base_url") and args.base_url:
                client.base_url = args.base_url

            if args.track_cmd == "register":
                # [追加] 安全確認: $19の決済エンドポイントであることの明示同意
                if not getattr(args, "pay", False):
                    import sys
                    sys.stderr.write("❌ Safety Check Failed: This is a paid endpoint. Use '--pay' to explicitly acknowledge the 19 USDC payment action.\n")
                    return

                pk = getattr(args, "private_key", None) or os.environ.get("AGENT_PRIVATE_KEY")
                if not pk:
                    print("❌ Error: AGENT_PRIVATE_KEY or --private-key is required to purchase a track.")
                    return
                
                # [追加] $19決済が弾かれないようにPaymentPolicyを上書き
                from .models import PaymentPolicy
                policy = PaymentPolicy(
                    max_spend_per_tx_usd=args.max_spend_usd,
                    max_spend_per_session_usd=args.max_spend_usd
                )
                
                client = LnChurchClient(private_key=pk, policy=policy)
                if hasattr(args, "base_url") and args.base_url:
                    client.base_url = args.base_url

                try:
                    res = client.register_verified_domain_track(
                        args.domain,
                        plan_id=args.plan,
                        idempotency_key=args.idempotency_key
                    )
                    
                    if args.proof_file:
                        client.save_verified_domain_track_proof(res, args.proof_file)

                    if args.json:
                        import json
                        exclude_fields = {"result_handle", "request_hash"} if not getattr(args, "include_proof", False) else None
                        safe_dump = res.model_dump(exclude=exclude_fields)
                        print(json.dumps(safe_dump, indent=2))
                    else:
                        print("✅ Domain-Control Verified Observation Track Lite purchased.\n")
                        print(f"Domain      : {res.domain}")
                        print(f"Request ID  : {res.request_id}")
                        print(f"Status      : {res.status}")
                        print(f"Track Plan  : {res.track_plan}")
                        if res.price:
                            print(f"Price       : {res.price.amount} {res.price.currency}")
                        if args.proof_file:
                            print(f"📄 Proof saved to: {args.proof_file}")

                except Exception as e:
                    import sys
                    if args.json:
                        sys.stderr.write(f"Error: {e}\n")
                    else:
                        print(f"❌ Track registration failed: {e}")

            elif args.track_cmd == "status":
                try:
                    res = client.get_verified_domain_track_status(args.request_id)
                    if not res:
                        print("❌ Failed: Request is not a verified domain track.")
                        return
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    else:
                        print(f"✅ Verified Domain Track Status for {res.request_id}:")
                        print(f"  Domain                      : {res.domain}")
                        print(f"  Track Plan                  : {res.track_plan}")
                        print(f"  Track Status                : {res.track_status}")
                        print(f"  Active Verified Track       : {res.is_active_verified_track}")
                        print(f"  Domain Control Verified     : {res.domain_control_verified}")
                        print(f"  Sponsor Verified            : {res.sponsor_verified}")
                        print(f"  Sponsor Verification Status : {res.sponsor_verification_status}")
                        print(f"  Track Activated At          : {res.track_activated_at}")
                        print(f"  Track Expires At            : {res.track_expires_at}")
                        print(f"  Last Observed At            : {res.last_observed_at}")
                        print(f"  Next Observable At          : {res.next_observable_at}")
                        print(f"  Observation Interval Hours  : {res.observation_interval_hours}")
                        print(f"  Not Legal Ownership Proof   : {res.not_legal_ownership_proof}")
                        print(f"  Not A Recommendation        : {res.not_a_recommendation}")
                        print(f"  Not A Trust Score           : {res.not_a_trust_score}")
                except Exception as e:
                    print(f"❌ Failed: {e}")

            elif args.track_cmd == "domain":
                try:
                    res = client.get_domain_verified_track(args.domain)
                    if not res:
                        print("❌ Failed: Domain not found or error occurred.")
                        return
                    if args.json:
                        print(res.model_dump_json(indent=2))
                    else:
                        print(f"✅ Verified Domain Track for {args.domain}:")
                        print(f"  Has Active Verified Track : {res.has_active_verified_domain_track}")
                        if res.current_track:
                            ct = res.current_track
                            print(f"  Request ID                : {ct.request_id}")
                            print(f"  Track Status              : {ct.track_status}")
                            print(f"  Track Plan                : {ct.track_plan}")
                            print(f"  Domain Control Verified   : {ct.domain_control_verified}")
                            print(f"  Last Observed At          : {ct.last_observed_at}")
                            print(f"  Next Observable At        : {ct.next_observable_at}")
                            print(f"  Observation Interval Hours: {ct.observation_interval_hours}")
                        print(f"  Safety Flags              : not_a_verdict={res.not_a_verdict}, not_a_recommendation={res.not_a_recommendation}, not_a_trust_score={res.not_a_trust_score}")
                except Exception as e:
                    print(f"❌ Failed: {e}")

    # 💡 [NEW] Internal Observatory (Internal Observatory Worker Tools)
    elif args.command == "observatory":
        from .client import LnChurchClient
        import os, json
        
        client = LnChurchClient(agent_id="internal_worker")
        if hasattr(args, "base_url") and args.base_url:
            client.base_url = args.base_url
            
        secret = getattr(args, "internal_secret", None) or os.environ.get("LN_CHURCH_INTERNAL_SECRET")
        
        if args.observatory_cmd == "targets" and args.targets_cmd == "claim":
            if not secret:
                print("❌ Error: --internal-secret or LN_CHURCH_INTERNAL_SECRET environment variable is required.")
                return
            try:
                res = client.claim_domain_observation_targets(observer=args.observer, limit=args.limit, internal_secret=secret)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Claimed {len(res.targets)} targets for observation.")
                    for t in res.targets:
                        print(f"  - {t.domain} (ID: {t.target_id})")
            except Exception as e:
                print(f"❌ Failed: {e}")

        elif args.observatory_cmd == "results" and args.results_cmd == "submit":
            if not secret:
                print("❌ Error: --internal-secret or LN_CHURCH_INTERNAL_SECRET environment variable is required.")
                return
            try:
                with open(args.file, "r") as f:
                    data = json.load(f)
                res = client.submit_domain_observation_result(data, internal_secret=secret)
                if args.json:
                    print(res.model_dump_json(indent=2))
                else:
                    print(f"✅ Result Submitted Successfully")
                    print(f"  Observation ID: {res.observation_id}")
            except Exception as e:
                print(f"❌ Failed: {e}")


if __name__ == "__main__":
    main()
