"""Closed current-condition input; never a tariff or an execution capability."""
import copy
import json
from ._contract_schema import load_economic_pack, validate, validate_atomic_amount, validate_safe_count
from .task_contract import jcs_canonical_bytes
import hashlib


def validate_economic_terms(family, value):
    bundle = load_economic_pack(family)
    schema = json.loads(bundle['resources']['economic-terms.schema.json'])
    validate(schema, value, root=schema)
    validate_safe_count(value['capacity_total'])
    for key, amount in value.items():
        if key.endswith('_atomic'):
            validate_atomic_amount(amount, allow_zero=key == 'creator_amount_atomic' or family == 'structured' and key == 'base_fee_atomic')
    for key, amount in value['reward'].items():
        if key.endswith('_atomic'):
            validate_atomic_amount(amount, allow_zero=family == 'immediate' and key == 'bonus_amount_atomic')
    if family == 'immediate' and int(value['reward']['maximum_amount_atomic']) != int(value['reward']['base_amount_atomic']) + int(value['reward']['bonus_amount_atomic']):
        raise ValueError('Invalid Immediate reward sum.')
    return copy.deepcopy(value)


def validate_offers(family, value):
    if type(value) is not dict or set(value) != {'schema_version', 'family', 'offers'} or value['schema_version'] != 'ln_church.task_economic_terms_offers.v1' or value['family'] != family or type(value['offers']) is not list:
        raise ValueError('Invalid economic offers envelope.')
    for offer in value['offers']:
        if type(offer) is not dict or 'economic_terms_digest' not in offer:
            raise ValueError('Invalid economic offer.')
        terms = validate_economic_terms(family, {k:v for k,v in offer.items() if k != 'economic_terms_digest'})
        if hashlib.sha256(jcs_canonical_bytes(terms)).hexdigest() != offer['economic_terms_digest']:
            raise ValueError('Invalid economic offer digest.')
    return copy.deepcopy(value)
