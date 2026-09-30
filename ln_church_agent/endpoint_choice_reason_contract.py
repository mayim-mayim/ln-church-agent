"""Fixed Architecture B–D primitives. No independent normative pack is generated."""
from __future__ import annotations

import hashlib
import re
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit

from .immediate_visit_contract import validate_timestamp, parse_timestamp, positive_bound
from .immediate_visit_profile import jcs_bytes
from .immediate_visit_contract import validate_endpoint_url
from .navigation import canonicalize_http_target
from .task_v2_contract import (
    PUBLIC_API_ORIGIN, PUBLIC_API_HOST, decode_json_object, validate_agent_id,
    validate_claim_token, validate_opaque_id, validate_task_id, validate_submission_id,
    validate_sha256, task_detail_path, task_claim_path, task_abandon_path,
    task_completion_path, task_status_path,
)

TASK_TYPE = 'endpoint_choice_reason.v1'
TASK_DEFINITION_VERSION = '1.0.0'
TASK_SCHEMA_VERSION = 'ln_church.agent_task.endpoint_choice_reason.v1'
PROFILE_ID = 'endpoint-choice-reason-jev-v1'
ASSET = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'
PLANS = {'C5': ('1000000', 5), 'C55': ('10000000', 55), 'C555': ('100000000', 555)}
TERMS_FIELDS = ('task_type', 'task_definition_version', 'task_definition_digest', 'question',
                'candidates', 'reveal_correct_set_after_answer', 'evaluation_profile_id', 'reward',
                'plan_id', 'registration_amount_atomic', 'capacity_total')
MAX_REPORT_BYTES = 16384
# DC-fixed Hondo c1 pack bytes; provenance is outside the normative pack.
PACK_SHA256 = {'SKILL.md': '2b86afc2f70bc1ded5f9390a973c4eb02a93f9bc18252788c7a488a40d6c9e16',
 'definition.json': '42038c72cd1eb1cc99c66f330fb8c20cbd5851dffc98d25e0ac40b0ff2e90d77',
 'evaluation-profile.json': 'b65971293afe9287bf3d81de2eb7cc83bf68e0d75f90d16983e85dc03142d2b6',
 'manifest.json': 'd5f9fb304584528ca9a797b8359db65e15e98f0494cbee132c8b0d6f0f0d4afa',
 'requester-guide.md': 'f6533f7b9cfb0f69cc8aa6144cd5383567b72696f487de74887e702104a2a7a1',
 'semantic-fixtures.json': '46bec4bcf71dbac7897bbb98fcea9e8adb494765389fc7d3caa9c175c0b8673e',
 'wire-contract.json': 'ed465a664f7ecb939ffb64b8be507ca5e300272518282f073d907647ff23b0a2'}
ERROR_CODES = {
    400: {'invalid_request', 'unsupported_task_profile', 'invalid_cursor'},
    401: {'invalid_claim_token'}, 404: {'task_not_found', 'not_found'},
    409: {'listing_ended', 'capacity_unavailable', 'active_claim_exists', 'once_per_offer_consumed',
          'idempotency_conflict', 'report_conflict', 'claim_not_active', 'report_already_accepted'},
    410: {'claim_expired'}, 422: {'report_binding_invalid'}, 503: {'temporarily_unavailable'},
}
OWNER_ERRORS = {400: {'invalid_request', 'invalid_cursor'},
                401: {'invalid_read_proof', 'read_proof_expired'},
                404: {'not_found'}, 503: {'temporarily_unavailable'}}


def prepare_url(value):
    """Apply Immediate URL syntax and normalization without Paid-only filters."""
    try:
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
        return validate_endpoint_url(normalized)
    except Exception:
        pass
    raise ValueError('Invalid endpoint choice URL.')


def schema(kind):
    return 'ln_church.' + kind + '.endpoint_choice_reason.v1'


def canonical_bytes(value, maximum=MAX_REPORT_BYTES):
    raw = jcs_bytes(value)
    if len(raw) > maximum:
        raise ValueError('Endpoint choice request exceeds size limit.')
    return raw


def digest(value):
    return hashlib.sha256(jcs_bytes(value)).hexdigest()


def text_value(value, maximum):
    if type(value) is not str or not value.strip() or len(value.encode('utf-8')) > maximum:
        raise ValueError('Invalid endpoint choice text.')
    return value


def candidate_id(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', value) is None:
        raise ValueError('Invalid candidate ID.')
    return value


def address(value):
    if type(value) is not str or re.fullmatch(r'0x[0-9a-fA-F]{40}', value) is None or int(value, 16) == 0:
        raise ValueError('Invalid reward address.')
    return value.lower()


def execution_id(value):
    if type(value) is not str or re.fullmatch(r'exec_[0-9a-f]{32}', value) is None:
        raise ValueError('Invalid execution ID.')
    return value


def atomic(value):
    if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]*', value) is None:
        raise ValueError('Invalid atomic amount.')
    return value


def decimal_string(value):
    if (type(value) is not str or re.fullmatch(r'0|1|0\.[0-9]*[1-9]', value) is None
            or not Decimal('0') <= Decimal(value) <= Decimal('1')):
        raise ValueError('Invalid lossless decimal.')
    return value


def cursor(value):
    if value is not None and (type(value) is not str or not value or len(value.encode('utf-8')) > 8192):
        raise ValueError('Invalid cursor.')
    return value


def load_contract_pack():
    if not PACK_SHA256:
        raise ValueError('Fixed endpoint choice contract pack has not been received.')
    root = Path(__file__).parent / 'contracts' / 'v189-endpoint-choice-reason'
    if {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} != set(PACK_SHA256):
        raise ValueError('Invalid endpoint choice contract pack.')
    resources = {}
    for name, expected in PACK_SHA256.items():
        raw = (root / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Invalid endpoint choice contract pack.')
        resources[name] = raw
    manifest = decode_json_object(resources['manifest.json'], 2097152)
    if (manifest['task_type'] != TASK_TYPE or manifest['task_definition_version'] != TASK_DEFINITION_VERSION
            or manifest['task_definition_digest'] != digest(manifest['descriptor'])):
        raise ValueError('Invalid endpoint choice descriptor.')
    profile = decode_json_object(resources['evaluation-profile.json'], 2097152)
    if profile['profile_id'] != PROFILE_ID or digest(profile) != '1069a04022a942a24982f16ba2c8f75d72451a809bb54a17de859e0c286f05dc':
        raise ValueError('Invalid endpoint choice evaluation profile.')
    return dict(manifest=manifest, resources=resources)


def require_definition(value):
    validate_sha256(value)
    if value != load_contract_pack()['manifest']['task_definition_digest']:
        raise ValueError('Unsupported endpoint choice definition.')
    return value
