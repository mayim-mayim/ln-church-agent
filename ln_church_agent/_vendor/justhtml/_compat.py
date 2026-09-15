"""Python 3.8 support for the isolated JustHTML copy, without parser rules."""

from dataclasses import dataclass as _dataclass
from itertools import zip_longest
import sys
import typing


TypeAlias = getattr(typing, "TypeAlias", object)


def dataclass(_cls=None, **kwargs):
    """Retain upstream dataclasses; slots are unavailable before Python 3.10."""
    if sys.version_info < (3, 10):
        kwargs.pop("slots", None)
    if _cls is None:
        return _dataclass(**kwargs)
    return _dataclass(_cls, **kwargs)


def remove_prefix(value, prefix):
    return value[len(prefix):] if value.startswith(prefix) else value


def remove_suffix(value, suffix):
    return value[:-len(suffix)] if suffix and value.endswith(suffix) else value


def zip_strict(*iterables):
    """Preserve strict zip's equal-length requirement on Python 3.8 and 3.9."""
    missing = object()
    for row in zip_longest(*iterables, fillvalue=missing):
        if any(value is missing for value in row):
            raise ValueError("zip() arguments have different lengths")
        yield row
