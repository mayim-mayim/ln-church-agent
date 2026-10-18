"""Authenticated v3 journal storage; operator-owned key outside the journal.

PyCryptodome is already required by eth-hash[pycryptodome]. No key generation,
key replacement, external credential service or plaintext fallback runs here.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import stat

from Crypto.Cipher import AES

from ._private_file_io import read_bounded
from .immediate_visit_profile import jcs_bytes
from .task_journal import JournalError

STORAGE_SCHEMA = 'ln_church.structured_response_journal.encrypted.v1'
LEGACY_SCHEMA = 'ln_church.structured_response_journal.v3'
KEY_FILE_ENV = 'LN_CHURCH_STRUCTURED_RESPONSE_KEY_FILE'
RECOVERY_ACTIONS = {
    'JOURNAL_KEY_REQUIRED': 'configure_original_key_file_and_retry_same_journal',
    'JOURNAL_KEY_UNAVAILABLE': 'restore_original_key_file_access_and_retry_same_journal',
    'JOURNAL_KEY_MISMATCH': 'restore_original_key_file_and_retry_same_journal',
    'JOURNAL_DECRYPTION_FAILED': 'restore_original_key_and_journal_then_retry_same_journal',
    'JOURNAL_ENCRYPTION_FAILED': 'retain_original_journal_and_retry_after_storage_repair',
}


def _key(journal_path):
    configured = os.environ.get(KEY_FILE_ENV)
    if not configured:
        raise JournalError('JOURNAL_KEY_REQUIRED')
    descriptor = -1
    failed = False
    try:
        path = Path(configured)
        if not path.is_absolute():
            raise ValueError
        path = Path(os.path.abspath(str(path)))
        journal_root = os.path.abspath(str(journal_path.parent))
        if os.path.commonpath([str(path), journal_root]) == journal_root:
            raise ValueError
        if os.name == 'nt':
            local = os.environ.get('LOCALAPPDATA')
            if not local:
                raise ValueError
            allowed = os.path.abspath(str(Path(local) / 'ln-church-agent' / 'keys'))
            if os.path.commonpath([os.path.normcase(str(path)), os.path.normcase(allowed)]) != os.path.normcase(allowed):
                raise ValueError
        current = Path(path.anchor)
        for part in path.parent.parts[1:]:
            current = current / part
            info = os.lstat(str(current))
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & 0x400):
                raise ValueError
        parent = os.lstat(str(path.parent))
        if os.name != 'nt' and (stat.S_IMODE(parent.st_mode) != 0o700
                or hasattr(os, 'geteuid') and parent.st_uid != os.geteuid()):
            raise ValueError
        flags = os.O_RDONLY
        for name in ('O_NOFOLLOW', 'O_BINARY', 'O_NOINHERIT'):
            flags |= getattr(os, name, 0)
        descriptor = os.open(str(path), flags)
        info = os.fstat(descriptor)
        at_path = os.stat(str(path), follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 32
                or (info.st_dev, info.st_ino) != (at_path.st_dev, at_path.st_ino)
                or getattr(at_path, 'st_file_attributes', 0) & 0x400
                or os.name != 'nt' and (stat.S_IMODE(info.st_mode) != 0o600
                    or hasattr(os, 'geteuid') and info.st_uid != os.geteuid())):
            raise ValueError
        value = bytes(read_bounded(descriptor, 32))
        if len(value) != 32:
            raise ValueError
    except Exception:
        failed = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if failed:
        raise JournalError('JOURNAL_KEY_UNAVAILABLE')
    return value


def _header(handle, key):
    return dict(schema_version=STORAGE_SCHEMA, algorithm='AES-256-GCM',
        journal_handle=handle, key_id=hashlib.sha256(key).hexdigest())


def seal(payload, handle, journal_path):
    key = _key(journal_path)
    failed = False
    try:
        header = _header(handle, key)
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(jcs_bytes(header))
        ciphertext, tag = cipher.encrypt_and_digest(jcs_bytes(payload))
        return dict(header, nonce=nonce.hex(), tag=tag.hex(),
            ciphertext=base64.b64encode(ciphertext).decode('ascii'))
    except Exception:
        failed = True
    if failed:
        raise JournalError('JOURNAL_ENCRYPTION_FAILED')


def unseal(stored, handle, journal_path):
    # Require a usable key even before accepting a legacy plaintext journal.
    # Legacy input is fully validated by the journal before its atomic rewrite.
    key = _key(journal_path)
    if stored.get('schema_version') == LEGACY_SCHEMA:
        return stored, True
    header = _header(handle, key)
    if stored.get('journal_handle') != handle:
        raise JournalError('JOURNAL_STATE_CONFLICT')
    if stored.get('key_id') != header['key_id']:
        raise JournalError('JOURNAL_KEY_MISMATCH')
    failed = False
    try:
        if (set(stored) != set(header) | {'nonce', 'tag', 'ciphertext'}
                or any(stored[k] != value for k, value in header.items())
                or type(stored['nonce']) is not str
                or re.fullmatch(r'[0-9a-f]{24}', stored['nonce']) is None
                or type(stored['tag']) is not str
                or re.fullmatch(r'[0-9a-f]{32}', stored['tag']) is None
                or type(stored['ciphertext']) is not str):
            raise ValueError
        ciphertext = base64.b64decode(stored['ciphertext'], validate=True)
        if base64.b64encode(ciphertext).decode('ascii') != stored['ciphertext']:
            raise ValueError
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(stored['nonce']), mac_len=16)
        cipher.update(jcs_bytes(header))
        plaintext = cipher.decrypt_and_verify(ciphertext, bytes.fromhex(stored['tag']))
        from .task_v2_contract import decode_json_object
        return decode_json_object(plaintext, 2 * 1024 * 1024), False
    except Exception:
        failed = True
    if failed:
        raise JournalError('JOURNAL_DECRYPTION_FAILED')
