"""Finite descriptor operations; path and persistence policy stay with callers."""

import os
from pathlib import Path


def read_bounded(descriptor: int, maximum_bytes: int) -> bytearray:
    """Read at most limit + 1 bytes, retaining the caller's oversize check."""

    content = bytearray()
    while len(content) <= maximum_bytes:
        chunk = os.read(descriptor, min(65536, maximum_bytes + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    return content


def write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError
        view = view[written:]


def fsync_directory(directory: Path) -> None:
    """Complete POSIX rename durability; Windows has no directory fsync here."""

    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(str(directory), flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
