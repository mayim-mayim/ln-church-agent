import copy
import json
from pathlib import Path

import pytest

from ln_church_agent.payment_contract import (
    CANONICAL_REQUIREMENT_FIELDS,
    PaymentContractError,
    canonical_json,
    canonical_request_target,
    compute_requirement_hash,
    verify_canonical_payment_requirement,
    verify_l402_metadata,
    verify_request_binding,
    verify_requirement_expiry,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "canonical_l402_contract.json"


@pytest.fixture()
def contract_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_cross_repo_golden_requirement_hash(contract_fixture):
    requirement = contract_fixture["canonical_requirement"]

    assert set(requirement) == set(CANONICAL_REQUIREMENT_FIELDS)
    assert compute_requirement_hash(requirement) == (
        "sha256:d57ea95de29f919f9d3e293873faf4eba4fd716a2ab6b788fcb0f0f28f1acf33"
    )
    assert verify_canonical_payment_requirement(requirement) == requirement


def test_canonical_json_is_recursive_key_sorted_compact_utf8():
    value = {"z": [{"b": 2, "a": "祈り"}], "a": {"d": True, "c": "x"}}

    assert canonical_json(value) == (
        '{"a":{"c":"x","d":true},"z":[{"a":"祈り","b":2}]}'
    )


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("schema_version", "ln_church.canonical_payment_requirement.v2"),
        ("url_scheme", "http"),
        ("host", "other.test"),
        ("port", 444),
        ("origin", "https://other.test"),
        ("method", "POST"),
        ("resource_url", "https://provider.test/api/agent/benchmark/ping?x=1"),
        ("rail", "mpp"),
        ("authorization_scheme", "Payment"),
        ("asset_identifier", "lightning:msats"),
        ("chain", "other-chain"),
        ("network", "bitcoin-testnet"),
        ("decimals", 0),
        ("amount_atomic", "10001"),
        (
            "pay_to",
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        ("expires_at", "1700003601"),
        ("challenge_id", "ch_contract_l402_002"),
        (
            "payment_id",
            "730dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
        ),
        ("idempotency_key", "idem_contract_002"),
        ("credential_payload_hash", "sha256:" + "a" * 64),
        ("requirement_hash", "sha256:" + "b" * 64),
    ],
)
def test_every_frozen_field_tamper_is_rejected(
    contract_fixture, field, replacement
):
    requirement = copy.deepcopy(contract_fixture["canonical_requirement"])
    requirement[field] = replacement

    with pytest.raises(PaymentContractError):
        verify_canonical_payment_requirement(requirement)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"port": 443.0}),
        lambda value: value.update({"host": None}),
        lambda value: value.update({"unexpected": "field"}),
        lambda value: value.pop("payment_id"),
    ],
    ids=["float", "null", "extra", "missing"],
)
def test_noncanonical_shape_is_rejected(contract_fixture, mutation):
    requirement = copy.deepcopy(contract_fixture["canonical_requirement"])
    mutation(requirement)

    with pytest.raises(PaymentContractError):
        verify_canonical_payment_requirement(requirement)


def test_request_binding_accepts_default_port_normalization(contract_fixture):
    requirement = contract_fixture["canonical_requirement"]

    assert verify_request_binding(
        requirement,
        request_url="https://provider.test:443/api/agent/benchmark/ping",
        method="get",
    ) == requirement


@pytest.mark.parametrize(
    "request_url,method",
    [
        ("https://other.test/api/agent/benchmark/ping", "GET"),
        ("https://provider.test/api/agent/benchmark/ping?changed=1", "GET"),
        ("https://provider.test/api/agent/benchmark/ping", "POST"),
    ],
)
def test_request_binding_rejects_target_mutation(
    contract_fixture, request_url, method
):
    with pytest.raises(PaymentContractError):
        verify_request_binding(
            contract_fixture["canonical_requirement"],
            request_url=request_url,
            method=method,
        )


@pytest.mark.parametrize(
    "request_url",
    [
        "https://user:password@provider.test/api/agent/benchmark/ping",
        "ftp://provider.test/api/agent/benchmark/ping",
        "https://provider.test/api/agent/benchmark/ping#fragment",
    ],
)
def test_canonical_request_target_rejects_unsafe_url_forms(request_url):
    with pytest.raises(PaymentContractError):
        canonical_request_target(request_url, "GET")


def test_expiry_uses_deterministic_integer_clock(contract_fixture):
    requirement = contract_fixture["canonical_requirement"]

    assert verify_requirement_expiry(
        requirement, now=contract_fixture["clock_seconds"]
    ) == requirement
    with pytest.raises(PaymentContractError, match="expired"):
        verify_requirement_expiry(requirement, now=1_700_003_600)
    with pytest.raises(PaymentContractError, match="clock"):
        verify_requirement_expiry(requirement, now=True)


def test_known_l402_metadata_matches_golden_requirement(contract_fixture):
    requirement = contract_fixture["canonical_requirement"]

    assert verify_l402_metadata(
        requirement,
        contract_fixture["l402_metadata"],
        now=contract_fixture["clock_seconds"],
    ) == requirement


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("amount_atomic", "10001"),
        (
            "payment_hash",
            "730dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
        ),
        (
            "payee",
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        ("network", "bitcoin-testnet"),
        ("expires_at", "1700003601"),
    ],
)
def test_l402_metadata_tamper_is_rejected(
    contract_fixture, field, replacement
):
    metadata = copy.deepcopy(contract_fixture["l402_metadata"])
    metadata[field] = replacement

    with pytest.raises(PaymentContractError):
        verify_l402_metadata(
            contract_fixture["canonical_requirement"],
            metadata,
            now=contract_fixture["clock_seconds"],
        )
