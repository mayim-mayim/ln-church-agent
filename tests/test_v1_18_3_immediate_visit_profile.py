"""Supporting evidence against exact audited profile vectors and boundaries.

The adjacent fixture is copied unchanged from Charter 6390b7fc, blob
27ddb094ab55f8d4ce43513b9a5944d1294907f0. Expectations are never generated from
the implementation. This file does not declare Hondo acceptance or parity.
"""

import hashlib
import json
from pathlib import Path
import traceback

import pytest

from ln_church_agent import immediate_visit_profile as profile


_FIXTURE = Path(__file__).parent / "fixtures" / "v183-immediate-visit" / "profile-fixtures.json"
_VECTORS = json.loads(_FIXTURE.read_text(encoding="utf-8"))["vectors"]
_JSON_HEADERS = (("Content-Type", "application/json"),)


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda vector: vector["id"])
def test_exact_audited_profile_vectors(vector):
    body = bytes.fromhex(vector["body_hex"])
    result = profile.analyze_response(vector["status"], (("Content-Type", vector["content_type"]),), body)
    assert result["outcome"] == vector["expected_outcome"]
    if result["outcome"] == "inconclusive":
        assert result["reason"] == vector["expected_reason"]
        assert "structure_sha256" not in result and "body_sha256" not in result
        return
    assert result["structure_sha256"] == vector["expected_structure_sha256"]
    assert result["body_sha256"] == vector["expected_body_sha256"]
    text = body.decode("utf-8")
    text = text[1:] if text.startswith("\ufeff") else text
    # Raw synthetic preimages stay in this pure fixture check only.
    structure = profile._extract_structure(text, result["media_family"])
    assert structure == vector["expected_structure"]
    assert profile.jcs_bytes(structure) == vector["expected_jcs_utf8"].encode("utf-8")


def test_fixed_fixture_source_identity():
    data = _FIXTURE.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    assert blob == "27ddb094ab55f8d4ce43513b9a5944d1294907f0"
    assert len(_VECTORS) == 27


@pytest.mark.parametrize("arrays,overwrite,expected", [(63, False, "comparable"),
                                                        (64, False, "json_depth_exceeded"),
                                                        (64, True, "json_depth_exceeded")])
def test_lexical_depth_including_overwritten_members(arrays, overwrite, expected):
    body = b'{"a":' + b"[" * arrays + b"0" + b"]" * arrays
    body += b',"\\u0061":0}' if overwrite else b"}"
    result = profile.analyze_response(200, _JSON_HEADERS, body)
    assert result.get("reason", result["outcome"]) == expected


def test_brackets_in_strings_are_not_containers():
    body = b'{"a":"' + b"[" * 100 + b'\\\"' + b"]" * 100 + b'"}'
    assert profile.analyze_response(200, _JSON_HEADERS, body)["outcome"] == "comparable"


@pytest.mark.parametrize("extra,expected", [(0, "comparable"), (1, "body_limit_exceeded")])
def test_complete_body_cap(extra, expected):
    body = b'{"a":"' + b"x" * (2097144 + extra) + b'"}'
    result = profile.analyze_response(200, _JSON_HEADERS, body)
    assert result["body_bytes"] == 2097152 + extra
    assert result.get("reason", result["outcome"]) == expected


def test_arbitrary_rfc8259_number_magnitude_is_only_a_type():
    enormous_integer = b'{"n":' + b"9" * 10000 + b"}"
    assert profile.analyze_response(200, _JSON_HEADERS, enormous_integer)["structure_sha256"] == (
        "8feb6bfa3a1ec39598463049c4b22bab535013e0a0f0d84b05ed6ea2804b931c")


@pytest.mark.parametrize("body", [b'{"n":Infinity}', b'{"n":-Infinity}', b'{"n":01}',
                                  b'{"n":1.}', b'{"a":true}garbage', b'{"a":"\x01"}'])
def test_entire_json_syntax_is_checked(body):
    result = profile.analyze_response(200, _JSON_HEADERS, body)
    assert result["reason"] == "json_invalid"
    assert "body_sha256" not in result


@pytest.mark.parametrize("status", [200, 301, 302, 399, 402, 403, 404, 500, 599])
def test_non_2xx_is_comparable_with_qualifying_body(status):
    result = profile.analyze_response(status, _JSON_HEADERS, b'{"error":true}')
    assert result["outcome"] == "comparable"
    assert result["status"] == status


@pytest.mark.parametrize("status,headers,body,reason", [
    (206, _JSON_HEADERS, b'{"a":0}', "partial_response"),
    (304, _JSON_HEADERS, b"", "partial_response"),
    (200, _JSON_HEADERS + (("Content-Range", "bytes 0-6/7"),), b'{"a":0}', "partial_response"),
    (101, _JSON_HEADERS, b'{"a":0}', "http_invalid"),
    (200, _JSON_HEADERS, b"", "body_empty"),
    (200, _JSON_HEADERS, b'{"a":"\xff"}', "utf8_invalid"),
    (200, (), b'{"a":0}', "media_invalid"),
    (200, (("Content-Type", "text/plain"),), b'{"a":0}', "media_unsupported"),
    (200, (("Content-Type", "application/xhtml+xml"),), b"<p>X", "media_unsupported"),
    (200, (("Content-Type", "application/*+json"),), b'{"a":0}', "media_invalid"),
    (200, (("Content-Type", "text/html; charset=shift_jis"),), b"<p>X", "charset_unsupported"),
    (200, _JSON_HEADERS + (("Content-Encoding", "gzip"),), b'{"a":0}', "content_encoding_unsupported"),
    (200, _JSON_HEADERS + (("Content-Encoding", "identity, gzip"),), b'{"a":0}', "content_encoding_unsupported"),
    (200, _JSON_HEADERS + (("Content-Encoding", "identity"), ("content-encoding", "br")), b'{"a":0}', "content_encoding_unsupported"),
])
def test_failure_metadata_has_finite_reason_and_no_digest(status, headers, body, reason):
    result = profile.analyze_response(status, headers, body)
    assert result["outcome"] == "inconclusive"
    assert result["reason"] == reason
    assert "structure_sha256" not in result and "body_sha256" not in result


@pytest.mark.parametrize("headers", [
    (("Content-Type", 'Application/Problem+Json; CHARSET="UTF-8"'),),
    (("Content-Type", 'application/json; note="a,b;c"; charset="utf\\-8"'),),
    (("Content-Type", "application/json"), ("content-type", 'APPLICATION/JSON; charset="utf-8"')),
    _JSON_HEADERS + (("Content-Encoding", "identity, IDENTITY"), ("content-encoding", "identity")),
])
def test_valid_mime_normalization_preserves_multiplicity(headers):
    assert profile.analyze_response(200, headers, b'{"a":0}')["outcome"] == "comparable"


@pytest.mark.parametrize("headers", [
    (("Content-Type", "application/json; charset=utf-8; charset=UTF-8"),),
    (("Content-Type", 'application/json; charset="utf-8'),),
    (("Content-Type", "application/json, application/json"),),
    (("Content-Type", "application/json"), ("content-type", "text/html")),
    (("Content-Type", "application/json"), ("content-type", "application/json;charset=ascii")),
    (("Content-Type", "application/json; x="),),
    (("Content-Type", "application/json; x=abc\r\nCookie: secret"),),
])
def test_invalid_or_conflicting_mime_is_not_silently_selected(headers):
    assert profile.analyze_response(200, headers, b'{"a":0}')["reason"] == "media_invalid"


def test_single_bom_budget_observable_in_html_tree():
    # The second BOM creates body content and disables frameset admission.
    # Accidentally removing both admits frameset and drops the following <p>.
    raw = b'\xef\xbb\xbf\xef\xbb\xbf<frameset><frame></frameset><p>X'
    text = raw.decode("utf-8")[1:]
    structure = profile._extract_structure(text, "html")
    assert structure == {"kind": "html", "tags": [0, 0, 0, 0, 0, 0, 1, 0], "title": ""}
    result = profile.analyze_response(200, (("Content-Type", "text/html"),), raw)
    assert result["structure_sha256"] == "f75a3dfc33e04ca1aa1e9ec2bfb64a9f07e7a91a56f519df23aef0e85f88e338"
    assert result["body_sha256"] == hashlib.sha256(raw).hexdigest()
    assert profile.analyze_response(200, (("Content-Type", "text/html"),), raw[3:])["reason"] == "html_structure_empty"


def test_jcs_utf16_escaping_and_no_unicode_normalization():
    value = {"\ue000": 0, "😀": 1, "10": "/\n\u000f\u2028", "2": "e\u0301"}
    assert profile.jcs_bytes(value) == '{"10":"/\\n\\u000f\u2028","2":"e\u0301","😀":1,"\ue000":0}'.encode("utf-8")
    with pytest.raises(ValueError, match="^invalid_jcs_value$"):
        profile.jcs_bytes({"\ud800": 1})


@pytest.mark.parametrize("content_type,body", [
    ("application/json", b'{"REMOTE_SECRET_JSON_KEY":"Bearer abc"}'),
    ("text/html", b'<title>REMOTE_SECRET_TITLE</title><p>Bearer abc'),
    ("application/json", b'{"REMOTE_SECRET_BROKEN_KEY":"Bearer abc"'),
])
def test_raw_response_content_never_leaves_observation(content_type, body, caplog):
    result = profile.analyze_response(200, (("Content-Type", content_type), ("Set-Cookie", "REMOTE_SECRET_COOKIE")), body)
    visible = repr(result) + caplog.text
    assert "REMOTE_SECRET" not in visible and "Bearer abc" not in visible
    assert set(result) <= {"outcome", "status", "media_family", "body_bytes", "reason", "structure_sha256", "body_sha256"}


def test_parser_capability_failure_is_safe_exception_not_inconclusive(monkeypatch):
    def broken_parser(*_args, **_kwargs):
        raise RuntimeError("REMOTE_SECRET_PARSER_DETAIL")
    monkeypatch.setattr(profile, "JustHTML", broken_parser)
    with pytest.raises(RuntimeError, match="^immediate_visit_profile_processing_failed$") as captured:
        profile.analyze_response(200, (("Content-Type", "text/html"),), b"<p>X")
    displayed = "".join(traceback.format_exception(type(captured.value), captured.value, captured.value.__traceback__))
    assert "REMOTE_SECRET_PARSER_DETAIL" not in displayed
