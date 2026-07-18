import base64
import asyncio
import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import requests

from ln_church_agent.challenges import parse_challenge_from_response
from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import PaymentChallengeError, PaymentExecutionError
from ln_church_agent.models import (
    ChallengeSource,
    ExecutionContext,
    ParsedChallenge,
    TrustDecision,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "agent-server-l402-contract-v1.json"
FIXTURE_SHA256 = "acb32874e3761e89080bd3d0a7674f9cf214ea97a0633ca2598f9de32e349cc1"


def _fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _httpx_402(fixture, body=None, headers=None):
    request = fixture["request"]
    response = fixture["response"]
    return httpx.Response(
        response["status"],
        headers=headers or response["headers"],
        json=body or response["body"],
        request=httpx.Request(
            request["method"], request["url"], headers=request["headers"]
        ),
    )


def _requests_response(fixture, *, status=402, body=None, headers=None):
    request = fixture["request"]
    response = fixture["response"]
    prepared = requests.Request(
        request["method"], request["url"], headers=request["headers"]
    ).prepare()
    result = requests.Response()
    result.status_code = status
    result.headers.update(headers if headers is not None else response["headers"])
    result._content = json.dumps(
        body if body is not None else response["body"]
    ).encode("utf-8")
    result.request = prepared
    result.url = request["url"]
    return result


def _success_response(fixture):
    requirement = fixture["response"]["body"]["accepted_payments"][0][
        "canonical_requirement"
    ]
    claims = {
        "payment_id": requirement["payment_id"],
        "requirement_hash": requirement["requirement_hash"],
    }
    token = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return _requests_response(
        fixture,
        status=200,
        body={"status": "ok"},
        headers={
            "PAYMENT-RESPONSE": f'status="success", receipt="{token}"',
            "Payment-Receipt": token,
        },
    )


def _credential_views_with_macaroon(fixture, macaroon):
    body = copy.deepcopy(fixture["response"]["body"])
    headers = dict(fixture["response"]["headers"])
    credential = body["accepted_payments"][0]["credential_challenge"]
    original = credential["macaroon"]
    credential["macaroon"] = macaroon
    headers["WWW-Authenticate"] = headers["WWW-Authenticate"].replace(
        original, macaroon
    )
    return body, headers


def _set_requests_response_request(response, fixture, url):
    request = fixture["request"]
    response.request = requests.Request(
        request["method"],
        url,
        headers={**request["headers"], "Host": "provider.test"},
    ).prepare()
    response.url = url
    return response


def _client(fixture, wallet=None, **kwargs):
    wallet = wallet or MagicMock()
    wallet.pay_invoice.return_value = fixture["payment"]["mock_preimage"]
    client = Payment402Client(ln_adapter=wallet, **kwargs)
    client._clock = lambda: fixture["clock_unix_seconds"]
    return client, wallet


def test_fixture_is_byte_identical_to_frozen_server_blob():
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == FIXTURE_SHA256


def test_actual_server_response_parses_selected_canonical_l402_option():
    fixture = _fixture()
    parsed = parse_challenge_from_response(
        _httpx_402(fixture), now=fixture["clock_unix_seconds"]
    )
    requirement = fixture["response"]["body"]["accepted_payments"][0][
        "canonical_requirement"
    ]

    assert parsed.scheme == "L402"
    assert parsed._canonical_requirement == requirement
    assert parsed._atomic_amount == "10000"
    assert parsed.parameters["payment_id"] == requirement["payment_id"]


def test_actual_server_response_to_wallet_to_exact_server_credential_shape():
    fixture = _fixture()
    client, wallet = _client(fixture)
    request = fixture["request"]
    first = _requests_response(fixture)
    success = _success_response(fixture)
    selected = fixture["response"]["body"]["accepted_payments"][0]

    with patch(
        "ln_church_agent.client.requests.request", side_effect=[first, success]
    ) as transport:
        result = client.execute_detailed(
            request["method"], request["url"], headers=request["headers"]
        )

    expected_authorization = (
        "L402 "
        + selected["credential_challenge"]["macaroon"]
        + ":"
        + fixture["payment"]["mock_preimage"]
    )
    assert transport.call_args_list[1].kwargs["headers"]["Authorization"] == expected_authorization
    assert wallet.pay_invoice.call_count == 1
    assert result.settlement_receipt.present is True
    assert result.settlement_receipt.server_asserted is True
    assert result.settlement_receipt.signature_verified is False
    assert result.settlement_receipt.settlement_verified is True
    assert result.settlement_receipt.delivered is True
    assert result.settlement_receipt.receipt_format == "unsigned_base64json"
    raw_token = success.headers["Payment-Receipt"]
    assert result.settlement_receipt.receipt_token_hash == (
        "sha256:" + hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    )
    assert result.settlement_receipt.receipt_claims == {
        "payment_id": selected["canonical_requirement"]["payment_id"],
        "requirement_hash": selected["canonical_requirement"]["requirement_hash"],
    }
    assert result.settlement_receipt.receipt_token is None
    assert not any(
        key.casefold() in {"payment-response", "payment-receipt"}
        for key in result.response_headers
    )
    serialized = result.settlement_receipt.model_dump_json()
    assert raw_token not in serialized
    assert '"receipt_token":' not in serialized


def test_untrusted_receipt_claims_are_allowlisted_and_never_disclose_secrets():
    fixture = _fixture()
    requirement = fixture["response"]["body"]["accepted_payments"][0][
        "canonical_requirement"
    ]
    secret = "RECEIPT_PRIVATE_KEY_SECRET_91"
    claims = {
        "payment_id": requirement["payment_id"],
        "requirement_hash": requirement["requirement_hash"],
        "private_key": secret,
        "preimage": secret,
        "nested": {"token": secret},
    }
    raw_token = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    success = _requests_response(
        fixture,
        status=200,
        body={"status": "ok"},
        headers={
            "PAYMENT-RESPONSE": f'status="success", receipt="{raw_token}"',
            "Payment-Receipt": raw_token,
            "X-Public-Diagnostic": "visible",
        },
    )
    client, wallet = _client(fixture)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_requests_response(fixture), success],
    ):
        result = client.execute_detailed(
            fixture["request"]["method"],
            fixture["request"]["url"],
            headers=fixture["request"]["headers"],
        )

    serialized = result.model_dump_json()
    assert result.settlement_receipt.receipt_claims == {
        "payment_id": requirement["payment_id"],
        "requirement_hash": requirement["requirement_hash"],
    }
    assert result.settlement_receipt.receipt_token is None
    assert result.response_headers == {"X-Public-Diagnostic": "visible"}
    assert raw_token not in serialized
    assert secret not in serialized
    assert secret not in repr(result.settlement_receipt)
    wallet.pay_invoice.assert_called_once()


@pytest.mark.parametrize(
    "scheme,raw_proof",
    [
        ("L402", "00" * 32),
        ("exact", "0x" + ("ab" * 65)),
        ("lnc-evm-transfer", "tx-marker:hostile-raw-signature"),
    ],
)
def test_receipt_boundary_hashes_legacy_preimages_and_raw_signatures(
    scheme, raw_proof
):
    client = Payment402Client()
    parsed = ParsedChallenge(
        scheme=scheme,
        network="test-network",
        amount=1.0,
        asset="SATS" if scheme == "L402" else "USDC",
        parameters={},
        source=ChallengeSource.LEGACY_CUSTOM,
    )

    receipt = client._new_settlement_receipt(
        parsed,
        "test-network",
        raw_proof,
        None,
        "https://provider.test/paid",
    )

    expected = "sha256:" + hashlib.sha256(raw_proof.encode("utf-8")).hexdigest()
    serialized = receipt.model_dump_json()
    assert receipt.proof_reference == expected
    assert raw_proof not in serialized
    assert raw_proof not in repr(receipt)
    assert expected in serialized


def test_receipt_boundary_preserves_only_canonical_digest_and_none():
    client = Payment402Client()
    parsed = ParsedChallenge(
        scheme="exact",
        network="eip155:8453",
        amount=1.0,
        asset="USDC",
        parameters={},
        source=ChallengeSource.LEGACY_CUSTOM,
    )
    canonical = "sha256:" + ("a" * 64)

    canonical_receipt = client._new_settlement_receipt(
        parsed, "eip155:8453", canonical, None, "https://provider.test/paid"
    )
    absent_receipt = client._new_settlement_receipt(
        parsed, "eip155:8453", None, None, "https://provider.test/paid"
    )

    assert canonical_receipt.proof_reference == canonical
    assert absent_receipt.proof_reference is None


def test_integration_receipt_hashes_hostile_executor_proof_without_wire_leak():
    fixture = _fixture()
    raw_signature = "0x" + ("cd" * 65)
    expected = "sha256:" + hashlib.sha256(
        raw_signature.encode("utf-8")
    ).hexdigest()
    client, wallet = _client(fixture)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_requests_response(fixture), _success_response(fixture)],
    ), patch.object(
        client,
        "_process_payment",
        return_value=(raw_signature, "EVM", None),
    ):
        result = client.execute_detailed(
            fixture["request"]["method"],
            fixture["request"]["url"],
            headers=fixture["request"]["headers"],
        )

    serialized = result.model_dump_json()
    assert result.settlement_receipt.proof_reference == expected
    assert raw_signature not in serialized
    assert raw_signature not in repr(result.settlement_receipt)
    assert expected in serialized
    wallet.pay_invoice.assert_not_called()


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("amount_atomic", "10001"),
        ("asset_identifier", "lightning:btc"),
        ("network", "bitcoin-testnet"),
        ("decimals", 2),
        ("pay_to", "03" + "11" * 32),
        ("method", "POST"),
        ("resource_url", "https://provider.test/other"),
    ],
)
def test_canonical_field_tampering_is_rejected_before_wallet(field, replacement):
    fixture = _fixture()
    tampered = copy.deepcopy(fixture["response"]["body"])
    tampered["accepted_payments"][0]["canonical_requirement"][field] = replacement
    client, wallet = _client(fixture)

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture, body=tampered),
    ):
        with pytest.raises((PaymentChallengeError, PaymentExecutionError)):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    wallet.pay_invoice.assert_not_called()


def test_policy_hash_is_rechecked_after_trust_evaluator_before_wallet():
    fixture = _fixture()

    def mutate_after_policy(evidence, _context):
        evidence.challenge._canonical_requirement["amount_atomic"] = "10001"
        return TrustDecision(is_trusted=True, reason="mutation fixture")

    client, wallet = _client(fixture, trust_evaluators=[mutate_after_policy])
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture),
    ):
        with pytest.raises(
            PaymentExecutionError,
            match="canonical Server verifier|Canonical requirement",
        ):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    wallet.pay_invoice.assert_not_called()


def test_second_402_after_payment_never_calls_wallet_twice():
    fixture = _fixture()
    client, wallet = _client(fixture)
    response = _requests_response(fixture)
    with patch(
        "ln_church_agent.client.requests.request", side_effect=[response, response]
    ):
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    assert wallet.pay_invoice.call_count == 1


def test_concurrent_duplicate_operation_calls_wallet_once():
    fixture = _fixture()
    client, wallet = _client(fixture)
    context = ExecutionContext()
    request = fixture["request"]
    barrier = threading.Barrier(2)
    call_lock = threading.Lock()
    calls = 0

    def transport(*_args, **_kwargs):
        nonlocal calls
        with call_lock:
            calls += 1
            call_number = calls
        if call_number <= 2:
            barrier.wait(timeout=5)
            return _requests_response(fixture)
        return _success_response(fixture)

    def execute():
        return client.execute_detailed(
            request["method"], request["url"], headers=request["headers"], context=context
        )

    with patch("ln_church_agent.client.requests.request", side_effect=transport):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(execute) for _ in range(2)]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=10))
                except PaymentExecutionError:
                    outcomes.append(None)

    assert wallet.pay_invoice.call_count == 1
    assert sum(result is not None for result in outcomes) == 1


def test_wallet_timeout_is_ambiguous_and_explicitly_recoverable():
    fixture = _fixture()
    wallet = MagicMock()
    wallet.pay_invoice.side_effect = requests.Timeout("unknown submit result")
    client, _ = _client(fixture, wallet=wallet)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture),
    ):
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=context,
            )

    states = client.get_payment_operation_states(context)
    fingerprint, state = next(iter(states.items()))
    assert state["state"] == "ambiguous"
    assert client.resolve_ambiguous_payment(
        context, fingerprint, "confirmed_not_paid"
    ) == "confirmed_not_paid"


def test_header_body_invoice_mismatch_is_rejected_before_wallet():
    fixture = _fixture()
    headers = dict(fixture["response"]["headers"])
    headers["WWW-Authenticate"] = 'Payment invoice="<fetch-via-hateoas>"'
    client, wallet = _client(fixture)
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture, headers=headers),
    ):
        with pytest.raises((PaymentChallengeError, PaymentExecutionError)):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    wallet.pay_invoice.assert_not_called()


def test_server_x402_summary_split_view_is_rejected_before_wallet():
    fixture = _fixture()
    headers = dict(fixture["response"]["headers"])
    headers["x-402-payment-required"] = headers[
        "x-402-payment-required"
    ].replace("amount_atomic=10000", "amount_atomic=10001")
    client, wallet = _client(fixture)

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture, headers=headers),
    ):
        with pytest.raises((PaymentChallengeError, PaymentExecutionError)):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    wallet.pay_invoice.assert_not_called()


@pytest.mark.parametrize("macaroon", ["abcdefghij:split", "abcde fghij", "abcdefghij\t"])
def test_server_incompatible_macaroon_grammar_is_rejected_before_wallet(macaroon):
    fixture = _fixture()
    body = copy.deepcopy(fixture["response"]["body"])
    body["accepted_payments"][0]["credential_challenge"]["macaroon"] = macaroon
    client, wallet = _client(fixture)

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture, body=body),
    ):
        with pytest.raises((PaymentChallengeError, PaymentExecutionError)):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    wallet.pay_invoice.assert_not_called()


@pytest.mark.parametrize(
    "variant",
    ["malformed_base64", "truncated_packet", "amount_caveat_mismatch"],
)
def test_synchronized_body_and_www_macaroon_attack_fails_before_wallet(variant):
    """Matching body/header views cannot hide an unusable Server credential."""

    fixture = _fixture()
    original = fixture["response"]["body"]["accepted_payments"][0][
        "credential_challenge"
    ]["macaroon"]
    if variant == "malformed_base64":
        attacked = "="
    else:
        decoded = base64.b64decode(
            original + ("=" * (-len(original) % 4)),
            altchars=b"-_",
            validate=True,
        )
        if variant == "truncated_packet":
            attacked_bytes = decoded[:-1]
        else:
            assert b"cid amount=10\n" in decoded
            attacked_bytes = decoded.replace(
                b"cid amount=10\n", b"cid amount=11\n", 1
            )
        attacked = base64.b64encode(attacked_bytes).decode("ascii")

    body, headers = _credential_views_with_macaroon(fixture, attacked)
    client, wallet = _client(fixture)
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture, body=body, headers=headers),
    ):
        with pytest.raises((PaymentChallengeError, PaymentExecutionError)):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
            )
    wallet.pay_invoice.assert_not_called()


def test_pinned_sync_response_uses_logical_url_for_canonical_redirect_binding():
    fixture = _fixture()
    request = fixture["request"]
    start_url = "https://provider.test/start"
    pinned_url = "https://93.184.216.34/api/agent/benchmark/ping"

    redirect = requests.Response()
    redirect.status_code = 302
    redirect.headers["Location"] = request["url"]
    redirect._content = b""
    redirect.request = requests.Request(
        "GET", start_url, headers=request["headers"]
    ).prepare()
    redirect.url = start_url
    challenged = _set_requests_response_request(
        _requests_response(fixture), fixture, pinned_url
    )
    delivered = _set_requests_response_request(
        _success_response(fixture), fixture, pinned_url
    )
    client, wallet = _client(fixture, max_hops=2)
    client._navigation_resolver = lambda _host, _port: ("93.184.216.34",)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[redirect, challenged, delivered],
    ) as transport:
        result = client.execute_detailed(
            "GET", start_url, headers=request["headers"]
        )

    assert result.response == {"status": "ok"}
    assert result.final_url == request["url"]
    assert transport.call_args_list[1].args[1] == pinned_url
    assert transport.call_args_list[1].kwargs["headers"]["Host"] == "provider.test"
    wallet.pay_invoice.assert_called_once()


def test_pinned_async_response_uses_logical_url_for_canonical_redirect_binding():
    async def run():
        fixture = _fixture()
        request = fixture["request"]
        start_url = "https://provider.test/start"
        pinned_url = "https://93.184.216.34/api/agent/benchmark/ping"
        pinned_request = httpx.Request(
            request["method"],
            pinned_url,
            headers={**request["headers"], "Host": "provider.test"},
        )
        redirect = httpx.Response(
            302,
            headers={"Location": request["url"]},
            request=httpx.Request("GET", start_url, headers=request["headers"]),
        )
        challenged = httpx.Response(
            fixture["response"]["status"],
            headers=fixture["response"]["headers"],
            json=fixture["response"]["body"],
            request=pinned_request,
        )
        success_template = _success_response(fixture)
        delivered = httpx.Response(
            200,
            headers=dict(success_template.headers),
            json={"status": "ok"},
            request=pinned_request,
        )
        client, wallet = _client(fixture, max_hops=2)
        client._navigation_resolver = lambda _host, _port: ("93.184.216.34",)
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[redirect, challenged, delivered]
        )

        result = await client.execute_detailed_async(
            "GET", start_url, headers=request["headers"]
        )

        assert result.response == {"status": "ok"}
        assert result.final_url == request["url"]
        second = client._async_client.request.call_args_list[1]
        assert second.args[1] == pinned_url
        assert second.kwargs["headers"]["Host"] == "provider.test"
        assert second.kwargs["extensions"]["sni_hostname"] == "provider.test"
        wallet.pay_invoice.assert_called_once()

    asyncio.run(run())


@pytest.mark.parametrize(
    "headers",
    [
        {"Idempotency-Key": ""},
        {"Idempotency-Key": "  "},
        {"Idempotency-Key": "one", "idempotency-key": "two"},
    ],
)
def test_explicit_invalid_or_conflicting_idempotency_key_fails_before_transport(headers):
    client = Payment402Client(base_url="https://provider.test")
    with patch("ln_church_agent.client.requests.request") as transport:
        with pytest.raises(PaymentExecutionError, match="Idempotency-Key"):
            client.execute_detailed("GET", "/api", headers=headers)
    transport.assert_not_called()


def test_policy_rejection_does_not_register_payment_identity():
    fixture = _fixture()
    context = ExecutionContext()
    client, wallet = _client(fixture)
    client.policy.allowed_schemes = ["exact"]

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_requests_response(fixture),
    ):
        with pytest.raises(PaymentExecutionError, match="restricted"):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=context,
            )

    assert context._payment_identities == {}
    wallet.pay_invoice.assert_not_called()


def test_identity_conflict_check_is_atomic_and_does_not_partially_register():
    fixture = _fixture()
    parsed = parse_challenge_from_response(
        _httpx_402(fixture), now=fixture["clock_unix_seconds"]
    )
    requirement = parsed._canonical_requirement
    client, _wallet = _client(fixture)
    context = ExecutionContext()
    context._payment_identities[requirement["requirement_hash"]] = "other-operation"

    with pytest.raises(PaymentExecutionError, match="reused"):
        client._register_payment_identity(context, "this-operation", parsed)

    assert requirement["payment_id"] not in context._payment_identities
    assert context._payment_identities == {
        requirement["requirement_hash"]: "other-operation"
    }


def _assert_known_settled_recovery(client, wallet, context):
    states = client.get_payment_operation_states(context)
    fingerprint, state = next(iter(states.items()))
    assert state["state"] == "ambiguous"
    assert state["ambiguity_kind"] == "known_settled_delivery"
    assert state["ambiguous_reservation_usd"] == "0"
    assert context._ambiguous_reservations == {}
    assert wallet.pay_invoice.call_count == 1
    with pytest.raises(PaymentExecutionError, match="Known-settled"):
        client.resolve_ambiguous_payment(
            context, fingerprint, "confirmed_not_paid"
        )
    assert client.resolve_ambiguous_payment(
        context, fingerprint, "confirmed_paid"
    ) == "completed"
    assert client.get_payment_operation_states(context)[fingerprint][
        "ambiguity_kind"
    ] is None


def test_paid_retry_transport_failure_is_recoverable_without_second_reservation_sync():
    fixture = _fixture()
    client, wallet = _client(fixture)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_requests_response(fixture), requests.ReadTimeout("lost")],
    ):
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=context,
            )

    spent = client.policy._session_spent_usd
    assert spent > 0
    _assert_known_settled_recovery(client, wallet, context)
    assert client.policy._session_spent_usd == spent


def test_paid_retry_transport_failure_is_recoverable_without_second_reservation_async():
    async def run():
        fixture = _fixture()
        client, wallet = _client(fixture)
        context = ExecutionContext()
        request = httpx.Request(fixture["request"]["method"], fixture["request"]["url"])
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _httpx_402(fixture),
                httpx.ReadTimeout("lost", request=request),
            ]
        )

        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            await client.execute_detailed_async(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=context,
            )

        spent = client.policy._session_spent_usd
        assert spent > 0
        _assert_known_settled_recovery(client, wallet, context)
        assert client.policy._session_spent_usd == spent

    asyncio.run(run())
