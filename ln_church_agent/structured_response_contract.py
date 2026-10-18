"""APS c3 responder primitives. Backend owns the normative public pack.

Pack pins are populated only from a DC-fixed Backend intake. An absent pack
permits discovery but cannot authorize a new Claim or submission.
"""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

from .endpoint_choice_reason_contract import address, execution_id
from .immediate_visit_profile import jcs_bytes
from .task_v2_contract import (
    PUBLIC_API_ORIGIN, decode_json_object, validate_agent_id, validate_claim_token,
    validate_opaque_id, validate_task_id, validate_submission_id, validate_sha256,
    task_claim_path, task_detail_path, task_completion_path, task_status_path,
    task_abandon_path,
)
from .immediate_visit_contract import parse_timestamp, positive_bound

TASK_TYPE = 'structured_response.v3'
TASK_DEFINITION_VERSION = '3.0.0'
TASK_SCHEMA_VERSION = 'ln_church.agent_task.structured_response.v3'
MAX_REPORT_BYTES = 262144
MAX_ITEM_BYTES = 8192
MAX_RECOVERY_POSTS = 3
MAX_RECOVERY_SECONDS = 90.0
STATUSES = frozenset({'answered', 'unknown', 'not_disclosed', 'not_performed'})
PACK_DIRECTORY = 'v1814-structured-response-v3'
# DC-fixed B4 producer bytes; no locally generated normative pack.
PACK_SHA256 = {'SKILL.md': '22df87e9da2c04da10633c702cd737bd1cf240728606cdfb2d1681ecb0e111ce',
 'abandon.schema.json': '50821784dd5592630906fc32d9641d5e51d914151bbcfa3e3d50db63cec3e64c',
 'abandon_response.schema.json': '0e89de857a60c8846570a666c1fb737143cc4a6c3223944c9e826e28795148ef',
 'claim.schema.json': '2ad0c30606dac2adf096951155207c363db432157520148c286976cfd543d20d',
 'claim_request.schema.json': '7fe22483edc155c3b729d80af3e2e6fc89445c447cca231c5f2b922ba4e0fa17',
 'completion.schema.json': 'b0e89ba35192969390e56fdeb1c9883742c132ef99db54e2f17cd9ac8a14b2f1',
 'context.schema.json': '97dcae928b3b96c573274d2852d4fab405413498dee760cbbc8d65f48ffc15d7',
 'definition.json': 'fbe167c0d8f749ee7d2e67db834dd0e530c5865299b2398986bda4315b66cbe8',
 'error.schema.json': 'f6afe59e145563aeb307e43be299366b217e886008a5881225a69d866e1f630b',
 'evaluation-profile.json': 'c7189863ec8f276bf0b7d30dc92e9fd08a8ceb03ba07eb170ac44b185498b11c',
 'manifest.json': '42f46c805f6ef39de63e8716740697ece4c356f6197cc6129d3a40df52a26360',
 'page.schema.json': 'b01a813497aadac3b48f1d44e23e2c130a5d8ca463cb32a27c4096e0b0c8dce1',
 'question-bank.json': 'c98157b3ee1de54639074000a1d54608934162eb976d92ce2afb14793ed43bde',
 'receipt.schema.json': '2966873071118d8c24de7be9fc0ec78c75108cee4ab7997578a540b31a575e05',
 'registration.schema.json': 'c81c361e4b47fd63a5d56b77b68b459bf1ed021f5dd8f061032e8f0c9a0bb772',
 'requester-contract.json': 'a773e7d6a802896bc685fb15112a0045a20619bd0bb8cf1900cda90860e264d7',
 'requester-guide.md': '51372a61dae483f261f6acbaabeb492e8a0b330352f3584dec1431a5f4a40baa',
 'status.schema.json': 'd16075af25f7ff5649cad42def1262f46b6a11a96c36350194c3bcef6efb34b1',
 'task.schema.json': '9223e8a5c12518e0d8d3de7b5447e3f38f17429a918f4e81c98806eeba6f407b',
 'v3-registration-template.csv': 'c34ad60a87f34b787cbef37c6c21b6a5d946b8cc87eb1e0f924c1a48ec580b30',
 'wire-contract.json': 'cf7b88ccdfb80307ac6fdde07a1ac20c2e3c90b41f785dc6cbabe44db40c076e'}
PACK_SOURCE = {'commit': '235bc8de9ce60d32e467d2c1476cf9a6eeb6ab0e',
 'path': 'frontend/agent-task-specs/structured_response.v3/3.0.0',
 'repository': 'mayim-mayim/LN_Church',
 'task_definition_digest': '4d2b8f711b2273fba5215bbcfd767df1145d30a91ee9ea5711437e791616b274',
 'tree': 'db40a399648ff494c5e2298b25e03ccd9addc5cb'}


def schema(kind):
    return 'ln_church.' + kind + '.structured_response.v3'


def canonical_bytes(value, maximum=MAX_REPORT_BYTES):
    raw = jcs_bytes(value)
    if len(raw) > maximum:
        raise ValueError('Structured response exceeds byte limit.')
    return raw


def digest(value):
    return hashlib.sha256(jcs_bytes(value)).hexdigest()


def validate_wire(kind, value):
    from ._contract_schema import validate
    resources = load_contract_pack()['resources']
    definition = decode_json_object(resources[kind + '.schema.json'], 2097152)
    return validate(definition, value)


_TERM_FIELDS = ('task_type', 'task_definition_version', 'task_definition_digest',
    'title', 'description', 'items', 'participation', 'context_id', 'public_context',
    'aps_kind', 'plan_id', 'capacity_total', 'registration_amount_atomic', 'reward',
    'capacity_profile_id', 'evaluation_profile_id', 'evaluation_profile_digest',
    'visibility_profile_id', 'question_bank_version', 'question_bank_digest')


def validate_terms(value):
    terms = {key: value[key] for key in _TERM_FIELDS if key in value}
    if digest(terms) != value['terms_digest']:
        raise ValueError('Invalid structured response terms digest.')


def json_copy(value):
    return decode_json_object(canonical_bytes(value), MAX_REPORT_BYTES)


def text(value, maximum, *, nonempty=False):
    if (type(value) is not str or len(value.encode('utf-8')) > maximum
            or (nonempty and not value.strip())):
        raise ValueError('Invalid structured response text.')
    return value


def item_id(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', value) is None:
        raise ValueError('Invalid structured response item ID.')
    return value


def https_url(value):
    if value is None:
        return value
    text(value, 4096, nonempty=True)
    p = urlsplit(value)
    if (p.scheme != 'https' or not p.hostname or p.username or p.password
            or '\\' in value or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)):
        raise ValueError('Invalid HTTPS URL.')
    # Reading a value does not resolve or fetch it.
    _ = p.port
    return value


def cursor(value):
    if value is not None:
        text(value, 4096, nonempty=True)
    return value


def validate_participation(value):
    """Preserve server eligibility, including a blind source withheld on wire.

    This does not resolve a source or infer whether the Agent is eligible.
    Closed DTO validation uses the fixed producer pack.
    """
    if type(value) is not dict or value.get('mode') not in {'ANY', 'INCLUDE', 'EXCLUDE'}:
        raise ValueError('Invalid participation mode.')
    source = value.get('source_task_id')
    withheld = value.get('source_visibility') == 'withheld_for_blind'
    if withheld:
        if value['mode'] == 'ANY' or source is not None:
            raise ValueError('Invalid blind source projection.')
    elif value['mode'] in {'INCLUDE', 'EXCLUDE'}:
        validate_task_id(source)


def load_contract_pack():
    if not PACK_SHA256 or PACK_SOURCE is None:
        raise ValueError('DC-fixed Backend structured response pack has not been received.')
    root = Path(__file__).parent / 'contracts' / PACK_DIRECTORY
    if {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} != set(PACK_SHA256):
        raise ValueError('Invalid structured response pack inventory.')
    resources = {name: (root / name).read_bytes() for name in PACK_SHA256}
    if any(hashlib.sha256(raw).hexdigest() != PACK_SHA256[name] for name, raw in resources.items()):
        raise ValueError('Invalid structured response pack bytes.')
    manifest = decode_json_object(resources['manifest.json'], 2097152)
    if (manifest['task_type'] != TASK_TYPE
            or manifest['task_definition_version'] != TASK_DEFINITION_VERSION
            or manifest['task_definition_digest'] != digest(manifest['descriptor'])):
        raise ValueError('Invalid structured response definition.')
    for name, expected in manifest['descriptor']['files'].items():
        if len(resources[name]) != expected['bytes'] or hashlib.sha256(resources[name]).hexdigest() != expected['sha256']:
            raise ValueError('Invalid structured response descriptor resource.')
    for filename, field in [('definition.json', 'definition_sha256'),
                            ('wire-contract.json', 'wire_contract_sha256'),
                            ('evaluation-profile.json', 'evaluation_profile_sha256')]:
        if digest(decode_json_object(resources[filename], 2097152)) != manifest['descriptor'][field]:
            raise ValueError('Invalid structured response descriptor digest.')
    return dict(manifest=manifest, resources=resources, source=PACK_SOURCE)


def supported_tuple(value):
    if (value.get('schema_version') != TASK_SCHEMA_VERSION or value.get('task_type') != TASK_TYPE
            or value.get('task_definition_version') != TASK_DEFINITION_VERSION):
        return False
    try:
        return value.get('task_definition_digest') == load_contract_pack()['manifest']['task_definition_digest']
    except ValueError:
        return False


def require_tuple(value):
    if not supported_tuple(value):
        raise ValueError('Unsupported structured response tuple; update SDK or receive the fixed pack.')


def _fields(value, fields):
    if type(value) is not dict or set(value) - {x['field_id'] for x in fields}:
        raise ValueError('Unknown report field.')
    for f in fields:
        if f['field_id'] not in value:
            if f['required']:
                raise ValueError('Missing required report field.')
            continue
        v = value[f['field_id']]
        kind = f['type']
        if kind == 'string':
            text(v, 4096)
        elif kind == 'https_url_or_null':
            https_url(v)
        elif kind == 'boolean':
            if type(v) is not bool:
                raise ValueError('Expected boolean.')
        elif kind == 'number':
            if type(v) not in (int, float) or not math.isfinite(v):
                raise ValueError('Expected finite number.')
        elif kind == 'object_array':
            if type(v) is not list or not 1 <= len(v) <= f['max_items']:
                raise ValueError('Invalid bounded report array.')
            for row in v:
                _fields(row, f['fields'])
        else:
            raise ValueError('Unsupported report field type.')


def validate_definition_items(items):
    if (type(items) is not list or not 1 <= len(items) <= 22
            or len({x['item_id'] for x in items}) != len(items)
            or not any(x.get('required') is True for x in items)):
        raise ValueError('Invalid structured response definition items.')
    def check_fields(fields, *, child=False):
        if type(fields) is not list or not 1 <= len(fields) <= 10:
            raise ValueError('Invalid report fields.')
        if len({f['field_id'] for f in fields}) != len(fields):
            raise ValueError('Duplicate report field.')
        for f in fields:
            item_id(f['field_id'])
            if type(f.get('required')) is not bool or set(f) - {'field_id','type','required','max_items','fields'}:
                raise ValueError('Invalid report field.')
            if f['type'] == 'object_array':
                if child or type(f.get('max_items')) is not int or not 1 <= f['max_items'] <= 10:
                    raise ValueError('Recursive report schema is unsupported.')
                check_fields(f['fields'], child=True)
            elif f['type'] not in {'string','https_url_or_null','boolean','number'} or 'fields' in f or 'max_items' in f:
                raise ValueError('Invalid report field type.')
    for item in items:
        item_id(item['item_id'])
        if type(item.get('required')) is not bool or item.get('kind') not in {'text','choice','report'}:
            raise ValueError('Invalid item kind.')
        statuses = item['allowed_statuses']
        if (type(statuses) is not list or 'answered' not in statuses or len(set(statuses)) != len(statuses)
                or not set(statuses) <= STATUSES):
            raise ValueError('Invalid allowed statuses.')
        question = item['question']
        if type(question) is not dict or set(question) - {'en','ja'}:
            raise ValueError('Invalid question languages.')
        text(question['en'], 4096, nonempty=True)
        if question.get('ja') is not None:
            text(question['ja'], 4096, nonempty=True)
        if item['kind'] == 'choice':
            choices = item['choices']
            if type(choices) is not list or not 1 <= len(choices) <= 10 or len({x['choice_id'] for x in choices}) != len(choices):
                raise ValueError('Invalid choices.')
            for ch in choices:
                item_id(ch['choice_id']); text(ch['label']['en'],512,nonempty=True)
        elif item['kind'] == 'report' and 'report_fields' in item:
            check_fields(item['report_fields'])


def validate_answer(shared_assumptions, answers, definitions):
    if type(shared_assumptions) is not dict or set(shared_assumptions) != {'must','volume','outcome'}:
        raise ValueError('Invalid shared assumptions.')
    for v in shared_assumptions.values():
        text(v, 4096)
    if sum(len(v.encode('utf-8')) for v in shared_assumptions.values()) > 4096:
        raise ValueError('Shared assumptions exceed byte limit.')
    validate_definition_items(definitions)
    if type(answers) is not list or len(answers) > 22:
        raise ValueError('Invalid answer items.')
    by_id = {}
    for answer in answers:
        if (type(answer) is not dict or set(answer) - {'item_id','status','value','reason','evidence_mode'}
                or not {'item_id','status','value','reason'} <= set(answer)):
            raise ValueError('Invalid answer item fields.')
        key = item_id(answer['item_id'])
        if key in by_id:
            raise ValueError('Duplicate answer item.')
        canonical_bytes(answer, MAX_ITEM_BYTES)
        by_id[key] = answer
    if set(by_id) - {d['item_id'] for d in definitions}:
        raise ValueError('Answer is outside definition.')
    ordered = []
    for d in definitions:
        if d['item_id'] not in by_id:
            if d['required']:
                raise ValueError('Missing required answer entry.')
            continue
        a = by_id[d['item_id']]
        if a['status'] not in d['allowed_statuses']:
            raise ValueError('Status is not allowed by this item.')
        # APS fifth-axis evidence must be declared by the public definition.
        if 'evidence_mode' in a:
            if (d.get('axis') not in (5, '5') and d.get('aps_axis') not in (5,'5')):
                raise ValueError('Evidence mode is not permitted for this item.')
            if a['evidence_mode'] not in {'executed','specification_review','mixed','unknown'}:
                raise ValueError('Invalid evidence mode.')
        # Explanation quality is server-owned; only missing-status reasons
        # require nonempty text at the structural boundary.
        text(a['reason'], 8192, nonempty=a['status'] != 'answered')
        if a['status'] != 'answered':
            if a['value'] is not None:
                raise ValueError('Unknown/non-disclosed/unperformed value must be null.')
        elif d['kind'] == 'text':
            text(a['value'], 8192)
        elif d['kind'] == 'choice':
            if a['value'] not in {ch['choice_id'] for ch in d['choices']}:
                raise ValueError('Unknown choice ID.')
        else:
            if 'report_fields' not in d and d['item_id'] in {'a1_1','a1_2','a1_3','a1_4','category','competitors'}:
                _aps_report(a['value'],d['item_id'])
            else:
                _fields(a['value'], d['report_fields'])
        ordered.append(a)
    return json_copy({'shared_assumptions':shared_assumptions, 'items':ordered})


def _aps_report(value,key):
    if type(value) is not dict:
        raise ValueError('Invalid APS report.')
    expected={'a1_1':{'candidates','method'},'a1_3':{'candidates','method'},
        'a1_2':{'known_before_study'},'a1_4':{'identified','url','method'},
        'category':{'name'},'competitors':{'candidates'}}[key]
    if set(value)!=expected:
        raise ValueError('Invalid APS report fields.')
    if key=='a1_2':
        if type(value['known_before_study']) is not bool:
            raise ValueError('Expected prior recognition boolean.')
    if key=='a1_4':
        if type(value['identified']) is not bool:
            raise ValueError('Expected identification boolean.')
        https_url(value['url'])
    if 'name' in value:
        text(value['name'],4096,nonempty=True)
    if 'method' in value:
        text(value['method'],4096)
    if 'candidates' in value:
        rows=value['candidates']
        maximum={'a1_1':5,'a1_3':10,'competitors':3}[key]
        if type(rows) is not list or not (1 if key=='competitors' else 0)<=len(rows)<=maximum:
            raise ValueError('Invalid APS candidate count.')
        for row in rows:
            if type(row) is not dict or set(row)!={'name','url'}:
                raise ValueError('Invalid APS candidate.')
            text(row['name'],4096,nonempty=True);https_url(row['url'])
