"""Paid Service Trial contract primitives (audited specification 0f15a177)."""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .task_contract import jcs_canonical_bytes
from .task_v2_contract import (
    PUBLIC_API_ORIGIN, PUBLIC_API_HOST, CLAIM_TOKEN_HEADER, IDEMPOTENCY_KEY_HEADER,
    decode_json_object, validate_task_id, validate_submission_id, validate_opaque_id,
    validate_agent_id, validate_claim_token, validate_sha256, task_detail_path,
    task_claim_path, task_abandon_path, task_completion_path, task_status_path,
)
from .immediate_visit_contract import positive_bound, validate_timestamp
from .network_fetch import _canonical_https_url

TASK_TYPE = "paid_service_trial.v1"
TASK_SCHEMA_VERSION = "ln_church.agent_task.paid_service_trial.v1"
TASK_LIST_PATH = "/api/agent/tasks"
TASK_DEFINITION_VERSION = "1.0.0"
PROFILE_ID = "paid_service_trial_base_usdc_eip3009.v1"
NETWORK = "eip155:8453"
ASSET = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
MAX_REPORT_BYTES = 65536
MAX_HEADER_BYTES = 32768
MAX_BODY_BYTES = 2097152
ARTIFACT_PREFIX = "frontend/agent-task-specs/paid_service_trial.v1/1.0.0/"
ARTIFACT_NAMES = ("SKILL.md", "definition.json", "requester-guide.md", "v18-5-paid-service-trial-contract-v1.json", "wire-contract.json")
DEFINITION_URL = PUBLIC_API_ORIGIN + "/agent-task-specs/paid_service_trial.v1/1.0.0/manifest.json"
ERROR_SCHEMA_VERSION = "ln_church.task_error.paid_service_trial.v1"
ERROR_CODES_BY_STATUS = {
    400: {"invalid_request", "unsupported_task_profile", "invalid_cursor", "unsupported_purchase_terms"},
    401: {"invalid_claim_token"}, 404: {"task_not_found", "not_found", "sample_unavailable"},
    409: {"listing_ended", "capacity_unavailable", "active_claim_exists", "once_per_offer_consumed", "idempotency_conflict", "report_conflict", "claim_not_active", "report_already_accepted", "terms_changed", "sample_identity_conflict", "sample_not_ready", "payment_authorization_conflict"},
    410: {"claim_expired"}, 422: {"report_binding_invalid", "sample_binding_invalid"},
    503: {"temporarily_unavailable", "sample_temporarily_unavailable"},
}
SAFE_REASONS = {"receipt_pending", "witness_unavailable", "unsupported_witness", "network_mismatch", "asset_mismatch", "payer_mismatch", "recipient_mismatch", "amount_mismatch", "authorization_mismatch", "payment_before_claim", "transaction_failed", "payment_already_used", "verification_deadline", "witness_budget_exhausted"}


def digest(value: Any) -> str:
    return hashlib.sha256(jcs_canonical_bytes(value)).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    result = jcs_canonical_bytes(value)
    if len(result) > MAX_REPORT_BYTES:
        raise ValueError("Paid trial request too large.")
    return result


def address(value: Any) -> str:
    from eth_utils import is_checksum_address
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise ValueError("Invalid address.")
    if value != value.lower() and not is_checksum_address(value):
        raise ValueError("Invalid address checksum.")
    return value.lower()


def hash32(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]{64}", value):
        raise ValueError("Invalid hash.")
    return value


def uint(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,77}", value) or int(value) >= 2 ** 256:
        raise ValueError("Invalid uint256.")
    return value


def amount(value: Any) -> str:
    value = uint(value)
    if not 1 <= int(value) <= 10000:
        raise ValueError("Invalid purchase amount.")
    return value


def endpoint(value: Any) -> str:
    _canonical_https_url(value)
    # The same Immediate canonical URL and DNS boundary is retained.
    from .immediate_visit_contract import validate_endpoint_url
    from .redaction import is_secret_query_key, _contains_inspect_secret_material, _contains_inspect_path_secret_material
    parts = urlsplit(value)
    if (_contains_inspect_path_secret_material(parts.path)
            or any(is_secret_query_key(k) or _contains_inspect_secret_material(k) or _contains_inspect_secret_material(v)
                   for k,v in parse_qsl(parts.query,keep_blank_values=True))):
        raise ValueError('Secret-bearing endpoint is unsupported.')
    return validate_endpoint_url(value)


def instant_ms(value: Any) -> int:
    validate_timestamp(value, server=True)
    dt = datetime.fromisoformat(value[:-1] + "+00:00")
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000


def cursor(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,1024}", value):
        raise ValueError("Invalid cursor.")
    return value


def decode_base64_object(value: Any, maximum: int = MAX_HEADER_BYTES) -> dict:
    if not isinstance(value, str) or not 0 < len(value) <= maximum:
        raise ValueError("Invalid payment header.")
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value) or (('+' in value or '/' in value) and ('-' in value or '_' in value)):
        raise ValueError("Invalid payment header.")
    plain = value.rstrip("=")
    needed = (-len(plain)) % 4
    if needed == 3 or ('=' in value and len(value) % 4 != 0):
        raise ValueError("Invalid payment header.")
    raw = base64.b64decode(plain + '=' * needed, altchars=b'-_', validate=True)
    if base64.urlsafe_b64encode(raw).decode().rstrip('=') != plain.replace('+','-').replace('/','_'):
        raise ValueError("Invalid payment header.")
    return decode_json_object(raw, maximum)


def payment_response_locator(headers: Any, *, payer: str) -> Any:
    """An unverified locator only; malformed/absent headers return no locator."""
    try:
        pairs = list(headers.items()) if hasattr(headers, "items") else list(headers)
        if sum(len(k.encode('latin1')) + len(v.encode('latin1')) + 4 for k,v in pairs) > MAX_HEADER_BYTES:
            return None
        values = [v for k,v in pairs if k.lower() == 'payment-response']
        if not values or len(set(values)) != 1:
            return None
        data = decode_base64_object(values[0])
        if 'network' in data and data['network'] != NETWORK:
            return None
        if 'payer' in data and address(data['payer']) != address(payer):
            return None
        if 'success' in data and type(data['success']) is not bool:
            return None
        if any(k in data for k in ('transactionHash', 'txHash', 'chainId')):
            return None
        tx = data.get('transaction')
        if not isinstance(tx, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', tx):
            return None
        return tx.lower()
    except Exception:
        return None


def _load_v1_contract_bundle() -> dict:
    """Validate Backend-owned bytes, without generating a second contract pack."""
    root = Path(__file__).parent / 'contracts' / 'v185-paid-service-trial'
    try:
        manifest = decode_json_object((root / 'manifest.json').read_bytes(), MAX_BODY_BYTES)
        desc = manifest['descriptor']
        fixed = dict(schema_version='ln_church.task_definition_source_bundle.v1',
                     source_repository='mayim-mayim/LN_Church',
                     basis_commit='7fb401a9c2ba420b36566af068649d6a81d20515',
                     basis_tree='f8975740fecd58c70574b211044c9a0f5a5990ef',
                     specification_repository='mayim-mayim/LN_Church_Development-Charter',
                     specification_commit='0f15a177b52221e21fa40f851d648afc929d6e3d',
                     architecture_commit='4bf3532bd09468df87d93e5a0fcada96d7f7b808',
                     task_type=TASK_TYPE, task_definition_version=TASK_DEFINITION_VERSION, profile_id=PROFILE_ID)
        if (set(desc) != set(fixed) | {'fixture_blob','fixture_sha256','source_bundle_entries'}
                or any(desc.get(k) != v for k,v in fixed.items())
                or manifest['schema_version'] != 'ln_church.agent_task_source_bundle_manifest.v1'
                or manifest['source_repository'] != fixed['source_repository']
                or manifest['task_type'] != TASK_TYPE or manifest['task_definition_version'] != TASK_DEFINITION_VERSION
                or manifest['task_definition_digest_algorithm'] != 'sha256-rfc8785-jcs-descriptor-lowercase-hex-v1'
                or manifest['task_definition_digest'] != digest(desc)):
            raise ValueError
        entries = desc['source_bundle_entries']
        paths = [ARTIFACT_PREFIX + name for name in ARTIFACT_NAMES]
        if [e['path'] for e in entries] != paths or set(manifest['components']) != set(paths):
            raise ValueError
        resources = {}
        for name,e in zip(ARTIFACT_NAMES, entries):
            raw = (root / name).read_bytes()
            sha = hashlib.sha256(raw).hexdigest()
            blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if set(e) != {'path','mode','blob','sha256'} or e['mode'] != '100644' or e['blob'] != blob or e['sha256'] != sha or manifest['components'][e['path']]['sha256'] != sha:
                raise ValueError
            raw.decode('utf-8', errors='strict')
            resources[name] = raw
        entries_by_path = {e['path']: e for e in entries}
        fixture = entries_by_path[ARTIFACT_PREFIX + 'v18-5-paid-service-trial-contract-v1.json']
        wire = entries_by_path[ARTIFACT_PREFIX + 'wire-contract.json']
        if (desc['fixture_blob'] != fixture['blob'] or desc['fixture_sha256'] != fixture['sha256']
                or fixture['blob'] != 'ce68b83fc3ef1dd14c15910f39bd3a3fb98e9f87'
                or fixture['sha256'] != '4c46c6c5ac959f1562ae18be2d3b0965483d46659c3cc844549346d1460a0fb3'
                or len(resources['v18-5-paid-service-trial-contract-v1.json']) != 21407):
            raise ValueError
        definition = decode_json_object(resources['definition.json'], MAX_BODY_BYTES)
        expected_definition = dict(
            schema_version='ln_church.agent_task_definition.paid_service_trial.v1',
            task_type=TASK_TYPE, task_definition_version=TASK_DEFINITION_VERSION,
            semantic_contract_sha256=fixture['sha256'], wire_contract_sha256=wire['sha256'],
            reward=dict(network=NETWORK,asset='USDC',asset_address=ASSET,amount_atomic='20000'),
            plans=[dict(plan_id=plan,registration_amount_atomic=str(fee),capacity_total=capacity)
                   for plan,fee,capacity in [('C40',1000000,40),('C400',10000000,400),('C4000',100000000,4000)]],
            listing_duration_ms=172800000,report_window_ms=600000,verification_window_ms=3600000,
            repeat_policies=['ALLOW_REPEAT','ONCE_PER_OFFER_REWARD_ADDRESS'],
            purchase_profile=dict(x402_version=2,scheme='exact',authorization_method='EIP-3009',network=NETWORK,
                                  asset=ASSET,http_method='GET',minimum_amount_atomic='1',maximum_amount_atomic='10000'),
            guides=dict(worker='SKILL.md',requester='requester-guide.md'))
        if (jcs_canonical_bytes(definition) != resources['definition.json']
                or jcs_canonical_bytes(definition) != jcs_canonical_bytes(expected_definition)):
            raise ValueError
        return dict(manifest=manifest, definition=definition, resources=resources)
    except Exception:
        pass
    raise ValueError('Paid trial contract bundle unavailable or invalid.')


# V1 constants and serializers above are intentionally unchanged. Select a
# complete tuple; an unknown version must never fall back to GET or v1.
V2_TASK_TYPE = 'paid_service_trial.v2'
V2_TASK_SCHEMA_VERSION = 'ln_church.agent_task.paid_service_trial.v2'
V2_DEFINITION_URL = PUBLIC_API_ORIGIN + '/agent-task-specs/paid_service_trial.v2/2.0.0/manifest.json'
V2_TERMS_REASONS = frozenset({'expected_402', 'missing_payment_required',
    'invalid_payment_required', 'conflicting_payment_terms', 'resource_mismatch',
    'unsupported_payment_profile'})


def version_of(value: Any) -> str:
    kind = value.get('task_type') if isinstance(value, dict) else getattr(value, 'task_type', None)
    if kind == TASK_TYPE:
        return 'v1'
    if kind == V2_TASK_TYPE:
        return 'v2'
    raise ValueError('Invalid Paid Service Trial version.')


def validate_version(version: str) -> str:
    if version not in ('v1', 'v2'):
        raise ValueError('Invalid Paid Service Trial version.')
    return version


def _v2_number(value: Any) -> str:
    """ECMAScript shortest binary64 spelling with its decimal/exponent cutoffs."""
    import math
    if type(value) is int:
        if abs(value) > 9007199254740991:
            raise ValueError('Invalid JSON number.')
        return str(value)
    if not math.isfinite(value) or (value.is_integer() and abs(value) > 9007199254740991):
        raise ValueError('Invalid JSON number.')
    if value == 0:
        return '0'
    negative = value < 0
    text = repr(abs(value)).lower()
    coefficient, _, exponent = text.partition('e')
    whole, _, fraction = coefficient.partition('.')
    digits = whole + fraction
    point = len(whole) + (int(exponent) if exponent else 0)
    while len(digits) > 1 and digits[0] == '0':
        digits = digits[1:]; point -= 1
    digits = digits.rstrip('0') or '0'
    if 0 < point <= 21:
        result = (digits + '0' * (point - len(digits)) if point >= len(digits)
                  else digits[:point] + '.' + digits[point:])
    elif -6 < point <= 0:
        result = '0.' + '0' * -point + digits
    else:
        exp = point - 1
        result = digits[0] + ('.' + digits[1:] if len(digits) > 1 else '') + 'e' + ('+' if exp >= 0 else '') + str(exp)
    return ('-' if negative else '') + result


def v2_jcs_bytes(value: Any) -> bytes:
    """Scoped RFC8785 value domain; no Unicode normalization or old-hash change."""
    import json
    def encode(item: Any, depth: int = 0) -> str:
        if item is None: return 'null'
        if type(item) is bool: return 'true' if item else 'false'
        if type(item) in (int, float): return _v2_number(item)
        if type(item) is str:
            item.encode('utf-8', errors='strict')
            return json.dumps(item, ensure_ascii=False, separators=(',', ':'))
        if type(item) in (list, tuple, dict):
            if depth >= 64: raise ValueError('Invalid JSON depth.')
            if type(item) is dict:
                if any(type(k) is not str for k in item): raise ValueError('Invalid JSON key.')
                keys = sorted(item, key=lambda k: k.encode('utf-16-be', errors='strict'))
                return '{' + ','.join(encode(k) + ':' + encode(item[k], depth+1) for k in keys) + '}'
            return '[' + ','.join(encode(x, depth+1) for x in item) + ']'
        raise ValueError('Invalid JSON value.')
    return encode(value).encode('utf-8')


def v2_decode_json(raw: bytes, maximum: int = MAX_REPORT_BYTES) -> Any:
    """Check decimal integers before binary64 conversion, and decoded duplicates."""
    import json
    import math
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= maximum or raw.startswith(b'\xef\xbb\xbf'):
            raise ValueError
        def number(text: str) -> Any:
            coefficient, _, exponent = text.lower().lstrip('-').partition('e')
            whole, _, fraction = coefficient.partition('.')
            digits = (whole + fraction).lstrip('0')
            if digits:
                significant = digits.rstrip('0')
                # Only compare the exponent with a token-length bound. Beyond
                # it, positive scale is certainly unsafe integral; negative
                # scale is certainly fractional. Never allocate 10**exponent.
                bound = len(whole) + len(fraction) + 32
                magnitude = exponent.lstrip('+-').lstrip('0') or '0'
                limit = str(bound)
                power = (bound if len(magnitude) > len(limit)
                         or (len(magnitude) == len(limit) and magnitude > limit)
                         else int(magnitude))
                if exponent.startswith('-'): power = -power
                scale = power - len(fraction) + len(digits) - len(significant)
                if scale >= 0:
                    if len(significant) + scale > 16:
                        raise ValueError
                    if int(significant) * 10**scale > 9007199254740991:
                        raise ValueError
            value = float(text)
            if not math.isfinite(value) or (value.is_integer() and abs(value) > 9007199254740991):
                raise ValueError
            return value
        def pairs(items: Any) -> dict:
            result = {}
            for key, value in items:
                if key in result: raise ValueError
                result[key] = value
            return result
        def integer(text: str) -> int:
            value = int(text)
            if abs(value) > 9007199254740991: raise ValueError
            return value
        def invalid(_text: str) -> None: raise ValueError
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=number, parse_constant=invalid)
        v2_jcs_bytes(value)  # Validate every Unicode string/key and container depth.
        return value
    except Exception:
        pass
    raise ValueError('Invalid Paid Service Trial JSON.')


def v2_canonical_body(text: str) -> str:
    try:
        if type(text) is not str: raise ValueError
        raw = text.encode('utf-8')
        result = v2_jcs_bytes(v2_decode_json(raw, 16384))
        if len(result) > 16384: raise ValueError
        return result.decode('utf-8')
    except Exception:
        pass
    raise ValueError('Invalid Paid Service Trial JSON body.')


def v2_canonical_bytes(value: Any) -> bytes:
    raw = v2_jcs_bytes(value)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('Paid trial request too large.')
    return raw


def v2_digest(value: Any) -> str:
    return hashlib.sha256(v2_jcs_bytes(value)).hexdigest()


def version_digest(value: Any, version: str) -> str:
    return (digest if validate_version(version) == 'v1' else v2_digest)(value)


def version_bytes(value: Any, version: str) -> bytes:
    return (canonical_bytes if validate_version(version) == 'v1' else v2_canonical_bytes)(value)


def prepare_v2_url(value: Any) -> str:
    """Normalize incoming URLs only; retain the existing Paid target policy."""
    from .navigation import canonicalize_http_target
    try:
        # urlsplit/canonicalization can erase controls, fragments and empty
        # queries. Check rejected input before normalization; preserve query.
        if (type(value) is not str or not value.isascii() or len(value) > 2048
                or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)
                or '#' in value or '\\' in value):
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or parsed.port not in (None, 443):
            raise ValueError
        normalized = canonicalize_http_target(value).url
        if value.endswith('?') and not normalized.endswith('?'):
            normalized += '?'
        return endpoint(normalized)
    except Exception:
        pass
    raise ValueError('Invalid Paid Service Trial URL.')


def prepare_request(value: Any) -> dict:
    if type(value) is not dict or set(value) != {'method', 'url', 'body'}:
        raise ValueError('Invalid Paid Service Trial request input.')
    method = value['method']; url = prepare_v2_url(value['url'])
    if method == 'GET' and value['body'] is None:
        body = body_hash = content_type = None
    elif method == 'POST':
        body = v2_canonical_body(value['body'])
        body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()
        content_type = 'application/json'
    else:
        raise ValueError('Invalid Paid Service Trial request input.')
    result = dict(schema_version='ln_church.paid_service_request.v2', method=method,
                  url=url, content_type=content_type, body=body, body_sha256=body_hash)
    v2_canonical_bytes(result)
    return result


def validate_request(value: Any) -> dict:
    if type(value) is not dict or set(value) != {'schema_version', 'method', 'url', 'content_type', 'body', 'body_sha256'}:
        raise ValueError('Invalid Paid Service Trial request.')
    expected = prepare_request({k:value[k] for k in ('method', 'url', 'body')})
    if expected != value:
        raise ValueError('Invalid Paid Service Trial request binding.')
    return expected


def purchase_terms_digest(request: dict, terms: Any) -> str:
    from .paid_service_trial_models import PurchaseTerms
    request = validate_request(request)
    selected = PurchaseTerms.model_validate(terms)
    return v2_digest(dict(schema_version='ln_church.paid_service_purchase_binding.v2',
        request_digest=v2_digest(request), resource_url=request['url'], x402_version=2,
        authorization_method='EIP-3009', requirements=selected.requirements.wire()))


def target_request(claim: Any) -> Any:
    return claim.endpoint if version_of(claim) == 'v1' else claim.request.model_dump(mode='json')


def target_url(claim: Any) -> str:
    return claim.endpoint if version_of(claim) == 'v1' else claim.request.url


def load_contract_bundle(version: str = 'v1') -> dict:
    if validate_version(version) == 'v1':
        return _load_v1_contract_bundle()
    return _load_v2_contract_bundle()


# Fixed Backend c1 intake; retain these bytes independently of manifest claims.
V2_PACK_SOURCE_COMMIT = '860ff00950410c6e253670df79a3008062cf3c4b'
V2_PACK_SOURCE_TREE = '47babab7bc17e1aab2f0c7a1207fade60550985e'
V2_DEFINITION_DIGEST = '08723b869949844b04319bd395ba5f6f91c1aa9155e710929f1dc4168895da14'
V2_PACK_SHA256 = {
    'SKILL.md': '33683cc72cd44510ce4b9e3303b11f796007a71844ce8cf71e5c5131c1c72549',
    'definition.json': 'a05b9b86f015658a79fdbbeb4f4e0b26de9751bd2a1db0241f77b15a2f98b007',
    'manifest.json': '63c563767da3f7f4256895f23527f881b8138012bdff3e77a677e052d93f4aa1',
    'requester-guide.md': 'd04e399597194b19d8dd8bdd5ef8de38a5b0b95479ff6c6bd2afb8cd7c06bab4',
    'v18-5-paid-service-trial-contract-v2.json': '1e686341ee5293beeb0e3005881d24e0e8397996d07193044a571341a38fa7c4',
    'wire-contract.json': '4d558583ac7a332994b80ca4038246f3448dd3089e1598b2db8776e5b0ade549',
}


def _load_v2_contract_bundle() -> dict:
    """Validate the exact six-file Backend c1 pack, never a regenerated copy."""
    root = Path(__file__).parent / 'contracts' / 'v185-paid-service-trial-v2'
    prefix = 'frontend/agent-task-specs/paid_service_trial.v2/2.0.0/'
    names = ('SKILL.md', 'definition.json', 'requester-guide.md',
             'v18-5-paid-service-trial-contract-v2.json', 'wire-contract.json')
    try:
        actual = {name:(root/name).read_bytes() for name in V2_PACK_SHA256}
        if any(hashlib.sha256(raw).hexdigest() != V2_PACK_SHA256[name]
               for name, raw in actual.items()):
            raise ValueError
        manifest = decode_json_object(actual['manifest.json'], MAX_BODY_BYTES)
        if manifest['task_definition_digest'] != V2_DEFINITION_DIGEST:
            raise ValueError
        desc = manifest['descriptor']
        fixed = dict(schema_version='ln_church.task_definition_source_bundle.v1',
            source_repository='mayim-mayim/LN_Church',
            basis_commit='7fb401a9c2ba420b36566af068649d6a81d20515',
            basis_tree='f8975740fecd58c70574b211044c9a0f5a5990ef',
            specification_repository='mayim-mayim/LN_Church_Development-Charter',
            specification_commit='1e2946f150c3f69f1fae718f570faa4248b1a653',
            architecture_commit='9357ef1bbdf588f8764e1931af9a960a18cef8c8',
            task_type=V2_TASK_TYPE, task_definition_version='2.0.0',
            profile_id='paid_service_trial_base_usdc_eip3009.v2')
        if (set(desc) != set(fixed) | {'fixture_blob', 'fixture_sha256', 'source_bundle_entries'}
                or any(desc.get(k) != v for k,v in fixed.items())
                or manifest['schema_version'] != 'ln_church.agent_task_source_bundle_manifest.v1'
                or manifest['source_repository'] != fixed['source_repository']
                or manifest['task_type'] != V2_TASK_TYPE or manifest['task_definition_version'] != '2.0.0'
                or manifest['task_definition_digest_algorithm'] != 'sha256-rfc8785-jcs-descriptor-lowercase-hex-v1'
                or manifest['task_definition_digest'] != v2_digest(desc)):
            raise ValueError
        entries = desc['source_bundle_entries']; paths = [prefix+n for n in names]
        if [e['path'] for e in entries] != paths or set(manifest['components']) != set(paths):
            raise ValueError
        resources = {}
        for name, e in zip(names, entries):
            raw = actual[name]; sha = hashlib.sha256(raw).hexdigest()
            blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if (set(e) != {'path', 'mode', 'blob', 'sha256'} or e['mode'] != '100644'
                    or e['blob'] != blob or e['sha256'] != sha
                    or manifest['components'][e['path']]['sha256'] != sha):
                raise ValueError
            raw.decode('utf-8', errors='strict'); resources[name] = raw
        fixture = entries[3]; wire = entries[4]
        if (desc['fixture_blob'] != fixture['blob'] or desc['fixture_sha256'] != fixture['sha256']
                or fixture['blob'] != 'd3934a4b015364fdfaaf9ac29dbe0ec33a0bb74a'
                or fixture['sha256'] != '1e686341ee5293beeb0e3005881d24e0e8397996d07193044a571341a38fa7c4'
                or len(resources[names[3]]) != 62481):
            raise ValueError
        # Retain the v1 closed Definition's unchanged economics; add only §10.6.
        expected = dict(_load_v1_contract_bundle()['definition'])
        expected.update(schema_version='ln_church.agent_task_definition.paid_service_trial.v2',
            task_type=V2_TASK_TYPE, task_definition_version='2.0.0',
            semantic_contract_sha256=fixture['sha256'], wire_contract_sha256=wire['sha256'])
        profile = dict(expected['purchase_profile']); profile.pop('http_method')
        profile.update(http_methods=['GET', 'POST'], request_schema='ln_church.paid_service_request.v2',
            request_constraints=dict(post_content_type='application/json', canonicalization='RFC8785',
                max_input_body_bytes=16384, max_canonical_body_bytes=16384, max_container_depth=64,
                max_envelope_bytes=65536, minimum_safe_integer=-9007199254740991, maximum_safe_integer=9007199254740991))
        expected['purchase_profile'] = profile
        definition = decode_json_object(resources['definition.json'], MAX_BODY_BYTES)
        if v2_jcs_bytes(definition) != resources['definition.json'] or definition != expected:
            raise ValueError
        return dict(manifest=manifest, definition=definition, resources=resources)
    except Exception:
        pass
    raise ValueError('Paid trial v2 contract bundle unavailable or invalid.')
