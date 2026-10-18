"""Local validation of the bounded vocabulary in the fixed producer packs.

Schemas are shipped bytes, never caller URLs. No external references, fetching,
code evaluation or new package dependency is involved.
"""
import math
import re
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


def validate(schema, value, depth=0):
    if depth > 64 or type(schema) is not dict or set(schema) - _KEYS:
        raise ValueError('Unsupported fixed schema vocabulary.')
    if 'const' in schema and not _equal(value, schema['const']):
        raise ValueError('Invalid fixed contract constant.')
    if 'enum' in schema and not any(_equal(value, x) for x in schema['enum']):
        raise ValueError('Invalid fixed contract value.')
    if 'anyOf' in schema:
        for branch in schema['anyOf']:
            try:
                validate(branch, value, depth + 1)
                break
            except ValueError:
                continue
        else:
            raise ValueError('Invalid fixed contract variant.')
    if 'oneOf' in schema:
        matches = 0
        for branch in schema['oneOf']:
            try:
                validate(branch, value, depth + 1)
                matches += 1
            except ValueError:
                pass
        if matches != 1:
            raise ValueError('Invalid fixed contract exclusive variant.')
    for branch in schema.get('allOf', []):
        validate(branch, value, depth + 1)
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
            validate(properties[key], value[key], depth + 1)
    if type(value) is list:
        if not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', len(value)):
            raise ValueError('Invalid fixed contract array size.')
        if 'items' in schema:
            for item in value:
                validate(schema['items'], item, depth + 1)
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
