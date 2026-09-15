"""Pure, private extraction for the fixed immediate_visit_utf8.v1 profile.

Only digest and finite diagnostic metadata leave ``analyze_response``. Remote
body JSON is deliberately distinct from strict wire JSON: last decoded member
wins, arbitrary RFC 8259 numbers are accepted, and only extracted keys enter JCS.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional, Sequence, Tuple

from ._vendor.justhtml import JustHTML
from ._vendor.justhtml.parser.options import ParserOptions


PROFILE_ID = "immediate_visit_utf8.v1"
BODY_LIMIT = 2097152
JSON_DEPTH_LIMIT = 64
_HTML_TAGS = ("a", "form", "h1", "h2", "img", "meta", "p", "script")
_ASCII_SPACE = re.compile(r"[\t\n\f\r ]+")
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_NUMBER = object()


class _ProfileFailure(ValueError):
    """Contains a fixed reason only; never attach input or parser diagnostics."""


def jcs_bytes(value: Any) -> bytes:
    """RFC 8785 for the validated report/extracted-structure value domain.

    This domain has safe integers, strings, booleans, null, arrays and objects;
    it has no floating-point fields or remote numeric values. Reject values
    outside it rather than silently adopting Python's number serialization.
    """
    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if type(item) is bool:
            return "true" if item else "false"
        if type(item) is int:
            if abs(item) > 9007199254740991:
                raise ValueError("invalid_jcs_value")
            return str(item)
        if type(item) is str:
            # UTF-8 validation rejects lone surrogates; no Unicode normalization.
            item.encode("utf-8")
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if type(item) in (list, tuple):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("invalid_jcs_value")
            keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
            return "{" + ",".join(encode(key) + ":" + encode(item[key]) for key in keys) + "}"
        raise ValueError("invalid_jcs_value")

    try:
        return encode(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("invalid_jcs_value") from None


def _media_value(value: str) -> Tuple[str, str]:
    """Parse one MIME value without collapsing duplicates or quoted fields."""
    if not isinstance(value, str) or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value):
        raise _ProfileFailure("media_invalid")
    value = value.strip(" \t")
    match = _TOKEN.match(value)
    if match is None or match.end() == len(value) or value[match.end()] != "/":
        raise _ProfileFailure("media_invalid")
    major = match.group().lower()
    match = _TOKEN.match(value, match.end() + 1)
    if match is None:
        raise _ProfileFailure("media_invalid")
    minor = match.group().lower()
    if "*" in major or "*" in minor:
        raise _ProfileFailure("media_invalid")
    position = match.end()
    charset = None
    while position < len(value):
        while position < len(value) and value[position] in " \t":
            position += 1
        if position == len(value):
            break
        if value[position] != ";":
            raise _ProfileFailure("media_invalid")
        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        match = _TOKEN.match(value, position)
        if match is None:
            raise _ProfileFailure("media_invalid")
        name = match.group().lower()
        position = match.end()
        while position < len(value) and value[position] in " \t":
            position += 1
        if position == len(value) or value[position] != "=":
            raise _ProfileFailure("media_invalid")
        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        if position < len(value) and value[position] == '"':
            position += 1
            parts = []
            while position < len(value) and value[position] != '"':
                if value[position] == "\\":
                    position += 1
                    if position == len(value):
                        raise _ProfileFailure("media_invalid")
                parts.append(value[position])
                position += 1
            if position == len(value):
                raise _ProfileFailure("media_invalid")
            parameter = "".join(parts)
            position += 1
        else:
            match = _TOKEN.match(value, position)
            if match is None:
                raise _ProfileFailure("media_invalid")
            parameter = match.group()
            position = match.end()
        if name == "charset":
            if charset is not None:
                raise _ProfileFailure("media_invalid")
            charset = parameter.lower()
    return major + "/" + minor, "utf-8" if charset is None else charset


def _media(headers: Sequence[Tuple[str, str]]) -> Tuple[Optional[str], Optional[str]]:
    values = [value for name, value in headers if name.lower() == "content-type"]
    if not values:
        return None, "media_invalid"
    try:
        media = [_media_value(value) for value in values]
    except _ProfileFailure:
        return None, "media_invalid"
    if any(value != media[0] for value in media[1:]):
        return None, "media_invalid"
    essence, charset = media[0]
    if essence == "text/html":
        family = "html"
    elif essence == "application/json" or essence.startswith("application/") and essence.endswith("+json"):
        family = "json"
    else:
        family = None
    if charset != "utf-8":
        return family, "charset_unsupported"
    return family, None if family else "media_unsupported"


def inspect_response_headers(status: int, headers: Sequence[Tuple[str, str]]) -> Tuple[Optional[str], Optional[str]]:
    """Return a known media family and the first header-level finite reason."""
    family, media_reason = _media(headers)
    if type(status) is not int or status < 200 or status > 599:
        return family, "http_invalid"
    if status in (206, 304) or any(name.lower() == "content-range" for name, _ in headers):
        return family, "partial_response"
    encodings = [value for name, value in headers if name.lower() == "content-encoding"]
    for value in encodings:
        if any(token.strip(" \t").lower() != "identity" for token in value.split(",")):
            return family, "content_encoding_unsupported"
    return family, media_reason


def _check_json_depth(text: str) -> None:
    # Scan the *input* before last-member-wins parsing so an overwritten member
    # cannot hide an over-depth object/array. Brackets in strings do not count.
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > JSON_DEPTH_LIMIT:
                raise _ProfileFailure("json_depth_exceeded")
        elif char in "]}":
            depth -= 1


def _json_structure(text: str) -> Dict[str, Any]:
    _check_json_depth(text)

    def reject_constant(_value: str) -> Any:
        raise _ProfileFailure("json_invalid")

    try:
        parsed = json.loads(text, parse_int=lambda _value: _NUMBER,
                            parse_float=lambda _value: _NUMBER,
                            parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise _ProfileFailure("json_invalid") from None
    if type(parsed) is not dict or not parsed:
        raise _ProfileFailure("json_root_unsupported")
    members = {}
    for key, value in parsed.items():
        try:
            key.encode("utf-8")
        except UnicodeEncodeError:
            raise _ProfileFailure("json_structure_unavailable") from None
        if value is _NUMBER:
            kind = "number"
        elif value is None:
            kind = "null"
        elif type(value) is bool:
            kind = "boolean"
        elif type(value) is str:
            kind = "string"
        elif type(value) is list:
            kind = "array"
        else:
            kind = "object"
        members[key] = kind
    return {"kind": "json", "members": members}


def _document_nodes(root: Any):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        # JustHTML stores template contents in a separate fragment. Only
        # ordinary children are traversed; never descend template_content.
        children = node.children
        if children:
            stack.extend(reversed(children))


def _html_structure(text: str) -> Dict[str, Any]:
    try:
        document = JustHTML(text, sanitize=False, scripting_enabled=False,
                            fragment=False, collect_errors=False, debug=False,
                            _parser_opts=ParserOptions(discard_bom=False))
        counts = [0] * len(_HTML_TAGS)
        title = None
        for node in _document_nodes(document.root):
            if node.namespace not in (None, "html"):
                continue
            if node.name in _HTML_TAGS:
                counts[_HTML_TAGS.index(node.name)] += 1
            if node.name == "title" and title is None:
                title_text = "".join(child.data for child in _document_nodes(node)
                                     if child.name == "#text")
                title = _ASCII_SPACE.sub(" ", title_text).strip(" ")
        title = "" if title is None else title
    except Exception:
        # A broken runtime/parser is a capability failure, not a normal
        # no-reward observation. Suppress any source-bearing parser message.
        raise RuntimeError("immediate_visit_profile_processing_failed") from None
    if not title and not any(counts):
        raise _ProfileFailure("html_structure_empty")
    return {"kind": "html", "tags": counts, "title": title}


def _extract_structure(text: str, family: str) -> Dict[str, Any]:
    """Ephemeral preimage; internal only (fixed synthetic vector self-checks)."""
    if family == "json":
        return _json_structure(text)
    if family == "html":
        return _html_structure(text)
    raise _ProfileFailure("media_unsupported")


def analyze_response(status: int, headers: Sequence[Tuple[str, str]], body: bytes) -> Dict[str, Any]:
    """Extract one complete response; no network, persistence or reward logic.

    The transport owns framing/completion, byte/time budgets and DNS/TLS safety.
    This function repeats semantic header/body checks for pure synthetic use.
    Header multiplicity must be preserved by the caller. Diagnostics recording
    actual fetch start/finish belongs to the executor, not this pure function.
    """
    if type(body) is not bytes:
        raise TypeError("invalid_profile_body")
    family, reason = inspect_response_headers(status, headers)
    result = {"outcome": "inconclusive", "status": status if type(status) is int and 200 <= status <= 599 else None,
              "media_family": family, "body_bytes": len(body)}
    if reason is None and len(body) > BODY_LIMIT:
        reason = "body_limit_exceeded"
    if reason is None and not body:
        reason = "body_empty"
    if reason is None:
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            reason = "utf8_invalid"
    if reason is None:
        # Decode does not consume BOM. The parser is explicitly configured not
        # to consume one again: a second BOM remains ordinary parser input.
        if text.startswith("\ufeff"):
            text = text[1:]
        try:
            structure = _extract_structure(text, family)
        except _ProfileFailure as error:
            reason = str(error)
    if reason is not None:
        result["reason"] = reason
        return result
    result["outcome"] = "comparable"
    result["structure_sha256"] = hashlib.sha256(jcs_bytes(structure)).hexdigest()
    result["body_sha256"] = hashlib.sha256(body).hexdigest()
    return result
