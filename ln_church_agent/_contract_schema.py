"""Local validation of the bounded vocabulary in the fixed producer packs.

Schemas are shipped bytes, never caller URLs. No external references, fetching,
code evaluation or new package dependency is involved.
"""
import math
import re
import hashlib
from pathlib import Path
from datetime import datetime

_KEYS = frozenset({'$schema', '$id', 'title', 'description', 'type', 'const',
    'enum', 'anyOf', 'properties', 'required', 'additionalProperties', 'items',
    'minItems', 'maxItems', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern',
    'oneOf', 'allOf', 'uniqueItems', 'format', 'default'})


def _equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    return a == b


def validate_economic_revision(value):
    """Validate the opaque c2 condition identity, without a revision allowlist.

    This scalar check is not authentication or Task/Claim binding. The caller
    must still validate its DC-fixed family pack and complete terms snapshot.
    """
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9._~-]{1,128}', value) is None:
        raise ValueError('Invalid economic terms revision.')
    return value


def validate_atomic_amount(value, *, allow_zero=False):
    """Keep Base USDC atomic amounts lossless within the existing uint256 wire.

    Positive registration/reward bases and legitimate zero-valued outcomes
    are distinct call sites. No price table or missing-value default is used.
    """
    if (type(value) is not str
            or re.fullmatch(r'0|[1-9][0-9]{0,77}', value) is None
            or int(value) >= 2 ** 256 or (value == '0' and not allow_zero)):
        raise ValueError('Invalid economic atomic amount.')
    return value


def validate_safe_count(value, *, allow_zero=False):
    """Validate a capacity scalar; server admission remains a separate owner."""
    if type(value) is not int or not (0 if allow_zero else 1) <= value <= 9007199254740991:
        raise ValueError('Invalid economic count.')
    return value


def validate_plan_label(value, *, maximum):
    """Validate a pure product label using the received pack's length bound.

    A plan label neither selects a capability nor supplies a price/capacity.
    The family pack remains responsible for the complete closed structure.
    """
    if (type(maximum) is not int or maximum < 1 or type(value) is not str
            or not 1 <= len(value) <= maximum):
        raise ValueError('Invalid economic plan label.')
    return value


def validate_floor_amount(base_amount, coefficient, amount):
    """Check a server result against an already selected profile coefficient.

    The family owns thresholds, eligibility and compensation. This function
    only checks floor(base * coefficient) using integer arithmetic, without
    changing Decimal context or granting an entitlement.
    """
    validate_atomic_amount(base_amount)
    validate_atomic_amount(amount, allow_zero=True)
    if (type(coefficient) is not str
            or re.fullmatch(r'0|1|0\.[0-9]*[1-9]', coefficient) is None):
        raise ValueError('Invalid economic coefficient.')
    if '.' in coefficient:
        digits = coefficient[2:]
        numerator, denominator = int(digits), 10 ** len(digits)
    else:
        numerator, denominator = int(coefficient), 1
    if int(amount) != int(base_amount) * numerator // denominator:
        raise ValueError('Economic amount does not match saved basis.')
    return amount


def load_economic_pack(family):
    """Read only the DC-pinned immutable producer bytes for this family."""
    from .task_v2_contract import decode_json_object
    from .task_contract import jcs_canonical_bytes
    pin = ECONOMIC_PACKS.get(family)
    if pin is None:
        raise ValueError('Unsupported economic contract family.')
    root = Path(__file__).parent / 'contracts' / pin['directory']
    raw = (root / 'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin['manifest_sha256']:
        raise ValueError('Invalid economic contract manifest bytes.')
    manifest = decode_json_object(raw, 2097152)
    descriptor = manifest['descriptor']
    if (manifest['task_type'] != pin['task_type']
            or manifest['task_definition_version'] != pin['definition']
            or manifest['task_definition_digest'] != pin['digest']
            or hashlib.sha256(jcs_canonical_bytes(descriptor)).hexdigest() != pin['digest']):
        raise ValueError('Invalid economic contract identity.')
    prefix = 'frontend/agent-task-specs/' + pin['task_type'] + '/' + pin['definition'] + '/'
    resources = {'manifest.json': raw}
    for entry in descriptor['source_bundle_entries']:
        if not entry['path'].startswith(prefix):
            raise ValueError('Invalid economic contract resource path.')
        name = entry['path'][len(prefix):]
        if name in resources or '..' in Path(name).parts or Path(name).is_absolute():
            raise ValueError('Invalid economic contract resource path.')
        data = (root / name).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if (entry['mode'] != '100644' or entry['blob'] != blob
                or entry['sha256'] != hashlib.sha256(data).hexdigest()):
            raise ValueError('Invalid economic contract resource bytes.')
        resources[name] = data
    if set(resources) != {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}:
        raise ValueError('Invalid economic contract inventory.')
    return dict(manifest=manifest, resources=resources)


def validate_economic_wire(family, kind, value):
    from .task_v2_contract import decode_json_object
    resources = load_economic_pack(family)['resources']
    if family in ('paid', 'choice'):
        root = decode_json_object(resources['wire-contract.json'], 2097152)
        schema = root['$defs'][kind]
    else:
        root = schema = decode_json_object(resources[kind + '.schema.json'], 2097152)
    validate(schema, value, root=root)


def validate(schema, value, depth=0, *, root=None):
    keys = _KEYS | ({'$ref', '$defs', 'if', 'then', 'else', 'not', 'x-answer-contract'} if root is not None else set())
    if depth > 64 or type(schema) is not dict or set(schema) - keys:
        raise ValueError('Unsupported fixed schema vocabulary.')
    if 'not' in schema:
        try:
            validate(schema['not'], value, depth + 1, root=root)
        except ValueError:
            pass
        else:
            raise ValueError('Invalid excluded schema variant.')
    if '$ref' in schema:
        ref = schema['$ref']
        if type(ref) is not str or not ref.startswith('#/$defs/'):
            raise ValueError('Unsupported economic schema reference.')
        name = ref[len('#/$defs/'):]
        if '/' in name or name not in root.get('$defs', {}):
            raise ValueError('Invalid economic schema reference.')
        validate(root['$defs'][name], value, depth + 1, root=root)
    if 'if' in schema:
        try:
            validate(schema['if'], value, depth + 1, root=root)
        except ValueError:
            branch = 'else'
        else:
            branch = 'then'
        if branch in schema:
            validate(schema[branch], value, depth + 1, root=root)
    if 'const' in schema and not _equal(value, schema['const']):
        raise ValueError('Invalid fixed contract constant.')
    if 'enum' in schema and not any(_equal(value, x) for x in schema['enum']):
        raise ValueError('Invalid fixed contract value.')
    if 'anyOf' in schema:
        for branch in schema['anyOf']:
            try:
                validate(branch, value, depth + 1, root=root)
                break
            except ValueError:
                continue
        else:
            raise ValueError('Invalid fixed contract variant.')
    if 'oneOf' in schema:
        matches = 0
        for branch in schema['oneOf']:
            try:
                validate(branch, value, depth + 1, root=root)
                matches += 1
            except ValueError:
                pass
        if matches != 1:
            raise ValueError('Invalid fixed contract exclusive variant.')
    for branch in schema.get('allOf', []):
        validate(branch, value, depth + 1, root=root)
    kinds = schema.get('type')
    if kinds is not None:
        if type(kinds) is str:
            kinds = [kinds]
        match = {'object': type(value) is dict, 'array': type(value) is list,
            'string': type(value) is str, 'null': value is None,
            'boolean': type(value) is bool, 'integer': type(value) is int,
            'number': type(value) in (int, float) and math.isfinite(value)}
        if not any(match.get(kind, False) for kind in kinds):
            raise ValueError('Invalid fixed contract type.')
    if type(value) is dict:
        if not set(schema.get('required', [])) <= set(value):
            raise ValueError('Missing fixed contract field.')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and set(value) - set(properties):
            raise ValueError('Unknown fixed contract field.')
        for key in set(value) & set(properties):
            validate(properties[key], value[key], depth + 1, root=root)
    if type(value) is list:
        if not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', len(value)):
            raise ValueError('Invalid fixed contract array size.')
        if 'items' in schema:
            for item in value:
                validate(schema['items'], item, depth + 1, root=root)
        if schema.get('uniqueItems') and any(_equal(a, b) for i, a in enumerate(value) for b in value[i+1:]):
            raise ValueError('Duplicate fixed contract array item.')
    if type(value) is str:
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', len(value)):
            raise ValueError('Invalid fixed contract string size.')
        if 'pattern' in schema and re.search(schema['pattern'], value) is None:
            raise ValueError('Invalid fixed contract string pattern.')
        if schema.get('format') == 'date-time':
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                raise ValueError('Invalid fixed contract datetime.')
    if type(value) in (int, float):
        if value < schema.get('minimum', value) or value > schema.get('maximum', value):
            raise ValueError('Invalid fixed contract numeric bound.')
    return value


# DC-fixed Backend c2: Structured is withheld by the 8f65e25 routing.
ECONOMIC_PACKS = {'scheduled': {'directory': 'v1816-scheduled-v1_1',
               'manifest_sha256': 'ec37480b8aaf426e09a837b5e8296aeea5352ed10b2e85e7fc976941355919f5',
               'digest': '1e0331dfe9ff1ca63b1002e9ccd530e2de8cf0b0dc751704c0190093d19227a7',
               'task_type': 'scheduled_http_get_batch.v1',
               'definition': '1.1.0'},
 'immediate': {'directory': 'v1816-immediate-visit-v3_1',
               'manifest_sha256': '25e8291c3e41c8390d6f8ab4fa2dd1120636c373cbed784522aa6c7abcfab53b',
               'digest': '9591ae9d321993c9e101693f02985b87dce59ebaf1f83f580994e8f3442dfb43',
               'task_type': 'immediate_http_visit.v3',
               'definition': '3.1.0'},
 'paid': {'directory': 'v1816-paid-service-trial-v3_1',
          'manifest_sha256': 'e4014482f2fc9e87921b6668e7961c60c36ec478e8e63a63da21db0681e5e407',
          'digest': '48b478927f0c1bad45a1d89f74cc8990243e408d883479022b17d33e2427ef62',
          'task_type': 'paid_service_trial.v3',
          'definition': '3.1.0'},
 'choice': {'directory': 'v1816-endpoint-choice-reason-v2_3',
            'manifest_sha256': '891cb9498c1937ac3c112b606ca86ca560895d79507d5aa06ea693c93c930c9b',
            'digest': '4c070bbf5fb2c5e1b658f0075fba9e0d6cfd5cb8a48d7191fe027431a72a11df',
            'task_type': 'endpoint_choice_reason.v2',
            'definition': '2.3.0'},
 'structured': {'directory': 'v1816-structured-response-v3_1',
                'manifest_sha256': '84db721e414d89168bfbdd7a61c0f2b2604bc0e7c54dc6ca6580969df16d1776',
                'digest': '290fdabf00b6e8d7858af52dff3783032ca71fe58aaed267a1622d831a70ac4c',
                'task_type': 'structured_response.v3',
                'definition': '3.1.0'}}
