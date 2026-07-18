import asyncio
import base64
import builtins
import copy
import hashlib
import inspect
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from decimal import Decimal
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import requests
from bolt11 import Bolt11, MilliSatoshi, Tags, decode as decode_bolt11, encode as encode_bolt11
from bolt11.models.tags import Tag, TagChar
from eth_account import Account
from eth_account.messages import encode_typed_data

from ln_church_agent.adapters.l402_delegate import (
    LightningLabsL402Executor,
    NativeL402Executor,
)
from ln_church_agent.challenges import (
    parse_challenge_from_response,
    parse_www_authenticate,
)
from ln_church_agent.client import LnChurchClient, Payment402Client
from ln_church_agent.crypto.evm import (
    LocalKeyAdapter,
    build_eip3009_typed_data,
    derive_eip3009_requirement_nonce,
    validate_eip3009_payload,
)
from ln_church_agent.crypto.lightning import decode_bolt11_amount_msats
from ln_church_agent.crypto.protocols import EVMSigner
from ln_church_agent.payment_contract import sha256_prefixed
from ln_church_agent.exceptions import (
    CounterpartyTrustError,
    InvoiceParseError,
    NavigationGuardrailError,
    PaymentExecutionError,
)
from ln_church_agent.evaluators import (
    RemoteOutcomeMatcher,
    RemoteTrustEvaluator,
)
from ln_church_agent.models import (
    ChallengeSource,
    EvidenceRepository,
    ExecutionContext,
    L402ExecutionReport,
    OutcomeSummary,
    ParsedChallenge,
    PaymentEvidenceRecord,
    PaymentPolicy,
    TrustDecision,
)


EVM_PRIVATE_KEY = "0x" + "1" * 64
EVM_SIGNER = Account.from_key(EVM_PRIVATE_KEY).address
BASE_NETWORK = "eip155:8453"
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DESTINATION = "0x1111111111111111111111111111111111111111"
OTHER_ADDRESS = "0x2222222222222222222222222222222222222222"
MACAROON = "macaroon-1234567890"
MAINNET_SVM = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
DEVNET_SVM = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
MAINNET_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
DEVNET_USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
TEST_PREIMAGE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


def _signed_invoice(msats):
    tags = Tags(
        [
            Tag(
                TagChar.payment_hash,
                hashlib.sha256(bytes.fromhex(TEST_PREIMAGE)).hexdigest(),
            ),
            Tag(TagChar.payment_secret, "22" * 32),
            Tag(TagChar.description, "v1.16.2 payment boundary"),
        ]
    )
    invoice = Bolt11(
        currency="bc",
        date=int(time.time()),
        amount_msat=MilliSatoshi(msats) if msats is not None else None,
        tags=tags,
    )
    return encode_bolt11(invoice, private_key="01".zfill(64))


def _corrupt_invoice(invoice):
    return invoice[:-1] + ("q" if invoice[-1] != "q" else "p")


def _transport_response(status, body=None, headers=None, url="https://buyer.test/start"):
    response = MagicMock()
    response.status_code = status
    response.headers = dict(headers or {})
    response.url = url
    response.content = json.dumps(body or {}).encode()
    response.text = json.dumps(body or {})
    response.json.return_value = body or {}
    return response


def _encode_requirement(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _exact_payload(accepted_overrides=None, outer_overrides=None, parameters=None):
    accepted = {
        "scheme": "exact",
        "network": BASE_NETWORK,
        "asset": BASE_USDC,
        "amount": "1000000",
        "payTo": DESTINATION,
    }
    accepted.update(accepted_overrides or {})
    payload = {
        "x402Version": 2,
        "accepts": [accepted],
        "resource": {
            "url": "https://buyer.test/start",
            "description": "boundary",
            "mimeType": "application/json",
        },
    }
    if parameters is not None:
        payload["parameters"] = parameters
    payload.update(outer_overrides or {})
    return payload


def _exact_402(payload=None, url="https://buyer.test/start"):
    requirement = payload or _exact_payload()
    return _transport_response(
        402,
        headers={"PAYMENT-REQUIRED": _encode_requirement(requirement)},
        url=url,
    )


def _l402_402(msats=1000, invoice=None, macaroon=MACAROON, url="https://buyer.test/start"):
    actual_invoice = _signed_invoice(msats) if invoice is None else invoice
    header = f'L402 macaroon="{macaroon}", invoice="{actual_invoice}"'
    return _transport_response(402, headers={"WWW-Authenticate": header}, url=url)


class _CaptureEvidence(EvidenceRepository):
    def __init__(self):
        self.records = []
        self.export_contexts = []
        self.import_urls = []
        self.import_contexts = []
        self.session_import_contexts = []

    def export_evidence(self, record, context):
        self.records.append(record)
        self.export_contexts.append(context)

    async def export_evidence_async(self, record, context):
        self.records.append(record)
        self.export_contexts.append(context)

    def import_evidence(self, target_url, context):
        self.import_urls.append(target_url)
        self.import_contexts.append(context)
        return []

    def import_session_evidence(self, context):
        self.session_import_contexts.append(context)
        return []

    async def import_session_evidence_async(self, context):
        self.session_import_contexts.append(context)
        return []


class _PersistentEvidence(_CaptureEvidence):
    """In-memory restart boundary for durable budget-journal tests."""

    def import_session_evidence(self, context):
        return [
            record for record in self.records
            if record.session_id == context.session_id
        ]

    async def import_session_evidence_async(self, context):
        return self.import_session_evidence(context)


class _FailingEvidence(_CaptureEvidence):
    SECRET = "DUMMY_EVIDENCE_REPO_SECRET_16_2"

    def __init__(self):
        super().__init__()
        self.export_calls = 0

    def export_evidence(self, record, context):
        self.export_calls += 1
        raise RuntimeError(self.SECRET)

    async def export_evidence_async(self, record, context):
        self.export_calls += 1
        raise RuntimeError(self.SECRET)


class _RejectIfCalledSigner:
    address = EVM_SIGNER

    def __init__(self):
        self.atomic_calls = 0

    def generate_eip3009_payload_atomic(self, **kwargs):
        self.atomic_calls += 1
        raise AssertionError("signer must not be called")

    def execute_lnc_evm_relay_settlement(self, *args, **kwargs):
        raise AssertionError("signer must not be called")

    def execute_lnc_evm_transfer_settlement(self, *args, **kwargs):
        raise AssertionError("signer must not be called")


@pytest.mark.parametrize("msats", [1, 999, 1000, 1_234_000])
def test_real_bolt11_decoder_returns_exact_msats(msats):
    invoice = _signed_invoice(msats)
    assert int(decode_bolt11(invoice).amount_msat) == msats
    assert decode_bolt11_amount_msats(invoice) == msats


def test_real_bolt11_decoder_rejects_checksum_corruption():
    with pytest.raises(ValueError, match="Fail-Closed"):
        decode_bolt11_amount_msats(_corrupt_invoice(_signed_invoice(1000)))


def test_real_bolt11_decoder_rejects_amountless_invoice():
    with pytest.raises(ValueError, match="Amountless"):
        decode_bolt11_amount_msats(_signed_invoice(None))


@pytest.mark.parametrize("placeholder", [None, "", "lnbc1", "<invoice>", "placeholder"])
def test_real_bolt11_decoder_rejects_placeholders(placeholder):
    with pytest.raises((TypeError, ValueError)):
        decode_bolt11_amount_msats(placeholder)


def test_bolt11_import_failure_is_fail_closed_without_decoder_mock(monkeypatch):
    real_import = builtins.__import__

    def import_with_bolt11_missing(name, *args, **kwargs):
        if name == "bolt11":
            raise ImportError("injected missing dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_with_bolt11_missing)
    with pytest.raises(ValueError, match="dependency is unavailable"):
        decode_bolt11_amount_msats(_signed_invoice(1000))


def test_l402_parser_sets_private_canonical_requirement_and_atomic_amount():
    invoice = _signed_invoice(1_234_000)
    parsed = parse_www_authenticate(
        f'L402 macaroon="{MACAROON}", invoice="{invoice}"'
    )

    assert parsed._invoice_msats == 1_234_000
    assert parsed._atomic_amount == "1234000"
    assert parsed._canonical_requirement is not None
    assert parsed._canonical_requirement.atomic_amount == "1234000"
    assert parsed._canonical_requirement.human_amount_decimal == Decimal("1234")
    assert "_atomic_amount" not in parsed.model_dump()
    assert "_canonical_requirement" not in parsed.model_dump()
    assert "_invoice_msats" not in parsed.model_dump()


@pytest.mark.parametrize(
    "invoice,macaroon",
    [
        (None, MACAROON),
        ("", MACAROON),
        ("lnbc1", MACAROON),
        ("<invoice>", MACAROON),
        (_corrupt_invoice(_signed_invoice(1000)), MACAROON),
        (_signed_invoice(1000), None),
        (_signed_invoice(1000), ""),
        (_signed_invoice(1000), "placeholder"),
        (_signed_invoice(1000), "<macaroon>"),
        (_signed_invoice(1000), "macaroon:split"),
        (_signed_invoice(1000), "macaroon split"),
    ],
    ids=[
        "missing-invoice",
        "empty-invoice",
        "short-invoice",
        "placeholder-invoice",
        "bad-checksum",
        "missing-macaroon",
        "empty-macaroon",
        "placeholder-macaroon",
        "angle-placeholder-macaroon",
        "colon-macaroon",
        "internal-whitespace-macaroon",
    ],
)
@pytest.mark.parametrize("executor_type", [NativeL402Executor, LightningLabsL402Executor])
def test_invalid_l402_never_calls_wallet(invoice, macaroon, executor_type):
    wallet = MagicMock()
    executor = executor_type(wallet)
    parsed = ParsedChallenge(
        scheme="L402",
        network="Lightning",
        amount=1.0,
        asset="SATS",
        parameters={"invoice": invoice, "macaroon": macaroon},
        source=ChallengeSource.STANDARD_WWW,
    )

    with pytest.raises(PaymentExecutionError, match="Invalid or missing"):
        executor.execute_l402("https://buyer.test/start", "GET", parsed, {}, {})
    wallet.pay_invoice.assert_not_called()


@pytest.mark.parametrize("executor_type", [NativeL402Executor, LightningLabsL402Executor])
def test_valid_l402_calls_wallet_once_after_real_decode(executor_type):
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    parsed = parse_www_authenticate(
        f'L402 macaroon="{MACAROON}", invoice="{_signed_invoice(1000)}"'
    )
    executor = executor_type(wallet)

    report = executor.execute_l402("https://buyer.test/start", "GET", parsed, {}, {})

    assert report.payment_performed is True
    wallet.pay_invoice.assert_called_once_with(parsed.parameters["invoice"])


@pytest.mark.parametrize(
    "macaroon",
    [
        None,
        "",
        " ",
        "dummy",
        "missing",
        "none",
        "null",
        "placeholder",
        "<macaroon>",
        " " + MACAROON,
        MACAROON + " ",
    ],
    ids=[
        "none",
        "empty",
        "whitespace",
        "dummy",
        "missing",
        "none-text",
        "null",
        "placeholder",
        "angle-placeholder",
        "leading-whitespace",
        "trailing-whitespace",
    ],
)
@pytest.mark.parametrize("delegated", [False, True], ids=["native", "delegated"])
def test_client_invalid_macaroon_fails_before_irreversible_reserve(
    delegated, macaroon
):
    wallet = MagicMock()
    delegate = MagicMock()
    client = Payment402Client(
        ln_adapter=wallet,
        l402_executor=delegate,
        prefer_lightninglabs_l402=delegated,
        l402_delegate_allowed_hosts=["buyer.test"],
    )
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_l402_402(macaroon=macaroon),
    ):
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert "Ambiguous" not in str(caught.value)
    wallet.pay_invoice.assert_not_called()
    delegate.execute_l402.assert_not_called()
    assert client.policy._session_spent_usd == 0
    assert context._ambiguous_reservations == {}
    assert set(context._payment_states.values()) == {"validation_failed"}


@pytest.mark.parametrize(
    "allowlist,expected_delegate_calls,expected_wallet_calls",
    [
        (["BUYER.TEST"], 0, 1),
        (["BUYER.TEST:8443"], 1, 0),
    ],
)
def test_l402_delegate_allowlist_uses_strict_netloc(
    allowlist, expected_delegate_calls, expected_wallet_calls
):
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    delegate = MagicMock()
    delegate.execute_l402.return_value = L402ExecutionReport(
        delegate_source="lightninglabs-delegated",
        authorization_value=f"L402 {MACAROON}:{TEST_PREIMAGE}",
        preimage=TEST_PREIMAGE,
        payment_hash=hashlib.sha256(bytes.fromhex(TEST_PREIMAGE)).hexdigest(),
        payment_performed=True,
        endpoint="https://buyer.test:8443/start",
    )
    client = Payment402Client(
        ln_adapter=wallet,
        l402_executor=delegate,
        prefer_lightninglabs_l402=True,
        l402_delegate_allowed_hosts=allowlist,
    )

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _l402_402(url="https://buyer.test:8443/start"),
            _transport_response(
                200, {"status": "paid"}, url="https://buyer.test:8443/start"
            ),
        ],
    ):
        result = client.execute_detailed(
            "GET", "https://buyer.test:8443/start"
        )

    assert result.response == {"status": "paid"}
    assert delegate.execute_l402.call_count == expected_delegate_calls
    assert wallet.pay_invoice.call_count == expected_wallet_calls


@pytest.mark.parametrize("shape", ["flat", "json", "json-details"])
def test_mpp_amount_and_currency_match_real_signed_invoice(shape):
    invoice = _signed_invoice(1_234_000)
    if shape == "flat":
        header = f'MPP invoice="{invoice}", amount="1234", currency="SATS"'
    else:
        request_body = {"invoice": invoice, "amount": "1234", "currency": "SATS"}
        if shape == "json-details":
            request_body = {"methodDetails": request_body}
        request = _encode_requirement(
            request_body
        )
        header = f'MPP id="id-1", method="lightning", intent="charge", request="{request}"'

    parsed = parse_www_authenticate(header)

    assert parsed._invoice_msats == 1_234_000
    assert parsed._atomic_amount == "1234000"
    assert parsed._canonical_requirement.atomic_amount == "1234000"


@pytest.mark.parametrize(
    "declared_amount,currency,expected_marker",
    [("1234.001", "SATS", -2), ("1234", "USD", -4)],
)
def test_mpp_rejects_real_invoice_amount_or_currency_mismatch(
    declared_amount, currency, expected_marker
):
    invoice = _signed_invoice(1_234_000)
    parsed = parse_www_authenticate(
        f'MPP invoice="{invoice}", amount="{declared_amount}", currency="{currency}"'
    )
    assert parsed._invoice_msats == expected_marker


def _mpp_header(invoice, *, shape, currency, amount=None):
    if shape == "flat":
        fields = [f'invoice="{invoice}"', f'currency="{currency}"']
        if amount is not None:
            fields.append(f'amount="{amount}"')
        return "MPP " + ", ".join(fields)
    request = {"invoice": invoice, "currency": currency}
    if amount is not None:
        request["amount"] = amount
    if shape == "json-details":
        request = {"methodDetails": request}
    return (
        'MPP id="id-1", method="lightning", intent="charge", request="'
        + _encode_requirement(request)
        + '"'
    )


def _payment_request_header(case, invoice):
    request = {
        "invoice": invoice,
        "amount": "1",
        "currency": "SATS",
    }
    outer_method = "lightning"
    outer_intent = "charge"

    if case == "partial":
        return f'Payment request="{_encode_requirement(request)}"'
    if case == "invalid-request":
        return (
            'Payment id="pay-1", method="lightning", intent="charge", '
            f'request="{_encode_requirement({})}", invoice="{invoice}", '
            'amount="1", currency="SATS"'
        )
    if case == "method-conflict":
        request["MeThOd"] = "eip3009"
    elif case == "intent-conflict-session":
        request["InTeNt"] = "SeSsIoN"
    elif case == "empty-auth-method":
        outer_method = ""
    elif case == "empty-auth-intent":
        outer_intent = ""
    elif case == "falsey-json-method":
        request["method"] = False
    elif case == "falsey-json-intent":
        request["intent"] = False
    elif case == "nonstring-json-method":
        request["method"] = {"rail": "lightning"}
    elif case == "nonstring-json-intent":
        request["intent"] = ["charge"]
    elif case == "duplicate-json-method":
        raw = (
            '{"invoice":' + json.dumps(invoice)
            + ',"amount":"1","currency":"SATS",'
            '"method":"lightning","MeThOd":"lightning"}'
        )
        return (
            'Payment id="pay-1", method="lightning", intent="charge", '
            f'request="{_encode_raw_json(raw)}"'
        )
    elif case == "duplicate-json-intent":
        raw = (
            '{"invoice":' + json.dumps(invoice)
            + ',"amount":"1","currency":"SATS",'
            '"intent":"charge","InTeNt":"charge"}'
        )
        return (
            'Payment id="pay-1", method="lightning", intent="charge", '
            f'request="{_encode_raw_json(raw)}"'
        )
    elif case == "duplicate-auth-method":
        return (
            'Payment id="pay-1", method="lightning", MeThOd="lightning", '
            f'intent="charge", request="{_encode_requirement(request)}"'
        )
    elif case == "duplicate-auth-intent":
        return (
            'Payment id="pay-1", method="lightning", intent="charge", '
            f'InTeNt="charge", request="{_encode_requirement(request)}"'
        )
    elif case == "nested-unsupported-method":
        request["methodDetails"] = {"method": "card"}
    elif case == "nested-session-intent":
        request["methodDetails"] = {"intent": "session"}
    elif case != "complete":
        raise AssertionError(f"unknown Payment request case: {case}")

    return (
        f'Payment id="pay-1", method="{outer_method}", '
        f'intent="{outer_intent}", request="{_encode_requirement(request)}"'
    )


PAYMENT_REQUEST_REJECTION_CASES = [
    pytest.param("partial", False, "payment-auth-draft-partial", id="partial-fallback-off"),
    pytest.param("partial", True, "payment-auth-draft-partial", id="partial-fallback-on"),
    pytest.param("invalid-request", False, "payment-auth-draft-invalid-request", id="invalid-fallback-off"),
    pytest.param("invalid-request", True, "payment-auth-draft-invalid-request", id="invalid-fallback-on"),
    pytest.param("method-conflict", False, "payment-auth-draft-invalid-request", id="method-conflict-fallback-off"),
    pytest.param("method-conflict", True, "payment-auth-draft-invalid-request", id="method-conflict-fallback-on"),
    pytest.param("intent-conflict-session", False, "payment-auth-draft-invalid-request", id="intent-conflict-fallback-off"),
    pytest.param("intent-conflict-session", True, "payment-auth-draft-invalid-request", id="intent-conflict-fallback-on"),
    pytest.param("complete", False, "payment-auth-draft", id="complete-fallback-off"),
    pytest.param("empty-auth-method", True, "payment-auth-draft-invalid-request", id="empty-auth-method"),
    pytest.param("empty-auth-intent", True, "payment-auth-draft-invalid-request", id="empty-auth-intent"),
    pytest.param("falsey-json-method", True, "payment-auth-draft-invalid-request", id="falsey-json-method"),
    pytest.param("falsey-json-intent", True, "payment-auth-draft-invalid-request", id="falsey-json-intent"),
    pytest.param("nonstring-json-method", True, "payment-auth-draft-invalid-request", id="nonstring-json-method"),
    pytest.param("nonstring-json-intent", True, "payment-auth-draft-invalid-request", id="nonstring-json-intent"),
    pytest.param("duplicate-json-method", True, "payment-auth-draft-invalid-request", id="duplicate-json-method"),
    pytest.param("duplicate-json-intent", True, "payment-auth-draft-invalid-request", id="duplicate-json-intent"),
    pytest.param("duplicate-auth-method", True, "payment-auth-draft-invalid-request", id="duplicate-auth-method"),
    pytest.param("duplicate-auth-intent", True, "payment-auth-draft-invalid-request", id="duplicate-auth-intent"),
    pytest.param("nested-unsupported-method", True, "payment-auth-draft-invalid-request", id="nested-unsupported-method"),
    pytest.param("nested-session-intent", True, "payment-auth-draft-invalid-request", id="nested-session-intent"),
]


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "case,allow_fallback,expected_shape", PAYMENT_REQUEST_REJECTION_CASES
)
def test_payment_request_rejection_is_pre_irreversible_and_retryable(
    async_mode, case, allow_fallback, expected_shape
):
    invoice = _signed_invoice(1000)
    response = _transport_response(
        402,
        headers={
            "WWW-Authenticate": _payment_request_header(case, invoice)
        },
    )
    wallet = MagicMock()
    delegate = MagicMock()
    signer = _RejectIfCalledSigner()
    evidence = _CaptureEvidence()
    context = ExecutionContext()
    client = Payment402Client(
        ln_adapter=wallet,
        evm_signer=signer,
        evidence_repo=evidence,
        l402_executor=delegate,
        prefer_lightninglabs_l402=True,
        l402_delegate_allowed_hosts=["buyer.test"],
        allow_legacy_payment_auth_fallback=allow_fallback,
    )

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(return_value=response)
            with pytest.raises(PaymentExecutionError):
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )
            first_transport_calls = client._async_client.request.call_count
            with pytest.raises(PaymentExecutionError):
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )
            return first_transport_calls, client._async_client.request.call_count

        first_transport_calls, total_transport_calls = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request", return_value=response
        ) as transport:
            with pytest.raises(PaymentExecutionError):
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
            first_transport_calls = transport.call_count
            with pytest.raises(PaymentExecutionError):
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
            total_transport_calls = transport.call_count

    assert decode_bolt11_amount_msats(invoice) == 1000
    assert client._last_parsed_challenge.draft_shape == expected_shape
    wallet.pay_invoice.assert_not_called()
    delegate.execute_l402.assert_not_called()
    assert signer.atomic_calls == 0
    assert first_transport_calls == 1
    assert total_transport_calls == 2
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0
    assert context._payment_executed is False
    assert client.last_receipt is None
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert len(evidence.records) == 2
    assert all(record.payment_performed is False for record in evidence.records)
    assert all(record.receipt_summary is None for record in evidence.records)
    assert all(record.session_spend_delta_usd == 0 for record in evidence.records)


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_complete_payment_draft_opt_in_preserves_legacy_execution(async_mode):
    invoice = _signed_invoice(1000)
    request = {
        "MeThOd": "LIGHTNING",
        "InTeNt": "charge",
        "invoice": invoice,
        "amount": "1",
        "currency": "SATS",
        "methodDetails": {"METHOD": "Lightning", "INTENT": "CHARGE"},
    }
    response = _transport_response(
        402,
        headers={
            "WWW-Authenticate": (
                'Payment id="pay-1", method="LiGhTnInG", intent="ChArGe", '
                f'request="{_encode_requirement(request)}"'
            )
        },
    )
    paid = _transport_response(200, {"status": "paid"})
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    delegate = MagicMock()
    signer = _RejectIfCalledSigner()
    evidence = _CaptureEvidence()
    context = ExecutionContext()
    client = Payment402Client(
        ln_adapter=wallet,
        evm_signer=signer,
        evidence_repo=evidence,
        l402_executor=delegate,
        prefer_lightninglabs_l402=True,
        l402_delegate_allowed_hosts=["buyer.test"],
        allow_legacy_payment_auth_fallback=True,
    )

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[response, paid]
            )
            result = await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )
            return result, client._async_client.request

        result, transport = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[response, paid],
        ) as transport:
            result = client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert decode_bolt11_amount_msats(invoice) == 1000
    assert result.response == {"status": "paid"}
    assert client._last_parsed_challenge.draft_shape == "payment-auth-draft"
    assert client._last_parsed_challenge.payment_method == "lightning"
    assert client._last_parsed_challenge.payment_intent == "charge"
    wallet.pay_invoice.assert_called_once_with(invoice)
    delegate.execute_l402.assert_not_called()
    assert signer.atomic_calls == 0
    assert transport.call_count == 2
    assert transport.call_args_list[1].kwargs["headers"]["Authorization"] == (
        f"Payment {TEST_PREIMAGE}"
    )
    assert set(context._payment_states.values()) == {"completed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == pytest.approx(0.00065)
    assert len(evidence.records) == 1
    assert evidence.records[0].payment_performed is True
    assert evidence.records[0].receipt_summary is not None
    assert evidence.records[0].session_spend_delta_usd == pytest.approx(0.00065)


@pytest.mark.parametrize("rail", ["MPP", "L402"])
@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_payment_request_guard_preserves_legacy_lightning_rails(
    rail, async_mode
):
    invoice = _signed_invoice(1000)
    if rail == "MPP":
        header = f'MPP invoice="{invoice}", amount="1", currency="SATS"'
    else:
        header = f'L402 macaroon="{MACAROON}", invoice="{invoice}"'
    response = _transport_response(
        402, headers={"WWW-Authenticate": header}
    )
    paid = _transport_response(200, {"status": "paid"})
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    context = ExecutionContext()
    client = Payment402Client(
        ln_adapter=wallet,
        allow_legacy_payment_auth_fallback=False,
    )

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[response, paid]
            )
            result = await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )
            return result, client._async_client.request

        result, transport = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[response, paid],
        ) as transport:
            result = client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert decode_bolt11_amount_msats(invoice) == 1000
    assert result.response == {"status": "paid"}
    wallet.pay_invoice.assert_called_once_with(invoice)
    assert transport.call_count == 2
    assert transport.call_args_list[1].kwargs["headers"]["Authorization"].startswith(
        rail + " "
    )
    assert set(context._payment_states.values()) == {"completed"}
    assert context._ambiguous_reservations == {}


@pytest.mark.parametrize("shape", ["flat", "json", "json-details"])
def test_mpp_unknown_currency_without_amount_stops_before_wallet(shape):
    wallet = MagicMock()
    client = Payment402Client(ln_adapter=wallet)
    context = ExecutionContext()
    invoice = _signed_invoice(1000)
    response = _transport_response(
        402,
        headers={
            "WWW-Authenticate": _mpp_header(
                invoice, shape=shape, currency="USD"
            )
        },
    )

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[response, _transport_response(200, {"unexpected": True})],
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    wallet.pay_invoice.assert_not_called()
    assert transport.call_count == 1
    assert client._last_parsed_challenge._invoice_msats == -4
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}


@pytest.mark.parametrize("shape", ["flat", "json", "json-details"])
def test_mpp_sat_alias_positive_flow_reaches_wallet_once(shape):
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)
    invoice = _signed_invoice(1000)
    response = _transport_response(
        402,
        headers={
            "WWW-Authenticate": _mpp_header(
                invoice, shape=shape, currency="SAT", amount="1"
            )
        },
    )

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[response, _transport_response(200, {"status": "paid"})],
    ) as transport:
        result = client.execute_detailed("GET", "https://buyer.test/start")

    assert result.response == {"status": "paid"}
    wallet.pay_invoice.assert_called_once_with(invoice)
    assert transport.call_count == 2
    assert client._last_parsed_challenge.asset == "SATS"


@pytest.mark.parametrize(
    "shape,currency,amount,expected_marker",
    [
        ("flat", "SATS", "2", -2),
        ("json", "SATS", "2", -2),
        ("json-details", "SATS", "2", -2),
        ("flat", "USDC", "1", -4),
        ("json-details", "USDC", "1", -4),
    ],
)
def test_mpp_declared_amount_or_currency_mismatch_stops_before_wallet(
    shape, currency, amount, expected_marker
):
    wallet = MagicMock()
    client = Payment402Client(ln_adapter=wallet)
    context = ExecutionContext()
    response = _transport_response(
        402,
        headers={
            "WWW-Authenticate": _mpp_header(
                _signed_invoice(1000),
                shape=shape,
                currency=currency,
                amount=amount,
            )
        },
    )

    with patch(
        "ln_church_agent.client.requests.request", return_value=response
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    wallet.pay_invoice.assert_not_called()
    assert transport.call_count == 1
    assert client._last_parsed_challenge._invoice_msats == expected_marker
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}


def _encode_raw_json(raw_json):
    return base64.urlsafe_b64encode(raw_json.encode()).decode().rstrip("=")


def _mpp_boundary_header(case, invoice):
    other_invoice = _signed_invoice(2000)
    if case == "flat-case-mismatch":
        return f'MPP invoice="{invoice}", Amount="999999", Currency="USD"'
    if case == "flat-empty-currency":
        return f'MPP invoice="{invoice}", amount="1", currency=""'
    if case == "flat-empty-amount":
        return f'MPP invoice="{invoice}", amount="", currency="SATS"'
    if case == "flat-duplicate-case":
        return f'MPP invoice="{invoice}", amount="1", Amount="1", currency="SATS"'

    if case.startswith("top-"):
        invalid = {
            "top-empty-currency": ("currency", ""),
            "top-zero-currency": ("currency", 0),
            "top-false-currency": ("currency", False),
            "top-empty-amount": ("amount", ""),
            "top-zero-amount": ("amount", 0),
            "top-false-amount": ("amount", False),
            "top-noncanonical-amount": ("amount", "01"),
            "top-nan-amount": ("amount", "NaN"),
        }[case]
        request = {"invoice": invoice, "amount": "1", "currency": "SATS"}
        request[invalid[0]] = invalid[1]
        return f'MPP request="{_encode_requirement(request)}"'

    if case.startswith("details-"):
        invalid = {
            "details-empty-currency": ("currency", ""),
            "details-zero-currency": ("currency", 0),
            "details-false-currency": ("currency", False),
            "details-empty-amount": ("amount", ""),
            "details-zero-amount": ("amount", 0),
            "details-false-amount": ("amount", False),
        }[case]
        details = {"invoice": invoice, "amount": "1", "currency": "SATS"}
        details[invalid[0]] = invalid[1]
        return f'MPP request="{_encode_requirement({"methodDetails": details})}"'

    if case == "json-duplicate-case":
        raw = (
            '{"invoice":' + json.dumps(invoice)
            + ',"amount":"1","Amount":"1","currency":"SATS"}'
        )
        return f'MPP request="{_encode_raw_json(raw)}"'

    top = {"invoice": invoice, "amount": "1", "currency": "SATS"}
    details = {"invoice": invoice, "amount": "1", "currency": "SATS"}
    if case == "contradict-amount":
        details["amount"] = "2"
    elif case == "contradict-currency":
        details["currency"] = "SAT"
    elif case == "contradict-invoice":
        details["invoice"] = other_invoice
    elif case == "flat-request-invoice":
        request = _encode_requirement({"invoice": other_invoice})
        return f'MPP invoice="{invoice}", request="{request}"'
    top["methodDetails"] = details
    return f'MPP request="{_encode_requirement(top)}"'


@pytest.mark.parametrize(
    "case",
    [
        "flat-case-mismatch",
        "flat-empty-currency",
        "flat-empty-amount",
        "flat-duplicate-case",
        "top-empty-currency",
        "top-zero-currency",
        "top-false-currency",
        "top-empty-amount",
        "top-zero-amount",
        "top-false-amount",
        "top-noncanonical-amount",
        "top-nan-amount",
        "details-empty-currency",
        "details-zero-currency",
        "details-false-currency",
        "details-empty-amount",
        "details-zero-amount",
        "details-false-amount",
        "json-duplicate-case",
        "contradict-amount",
        "contradict-currency",
        "contradict-invoice",
        "flat-request-invoice",
    ],
)
def test_mpp_case_empty_falsey_duplicate_and_contradiction_fail_before_wallet(case):
    invoice = _signed_invoice(1000)
    wallet = MagicMock()
    context = ExecutionContext()
    client = Payment402Client(ln_adapter=wallet)
    response = _transport_response(
        402,
        headers={"WWW-Authenticate": _mpp_boundary_header(case, invoice)},
    )

    with patch(
        "ln_church_agent.client.requests.request", return_value=response
    ) as transport:
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    wallet.pay_invoice.assert_not_called()
    assert transport.call_count == 1
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert "ambiguous" not in str(caught.value).lower()
    assert invoice not in str(caught.value)


@pytest.mark.parametrize("shape", ["flat", "top", "details"])
def test_mpp_case_variant_fields_and_invoice_only_fallback_pay_once(shape):
    invoice = _signed_invoice(1000)
    if shape == "flat":
        header = f'MPP InVoIcE="{invoice}", AmOuNt="1", CuRrEnCy="sat"'
    elif shape == "top":
        header = "MPP request=\"{}\"".format(_encode_requirement({
            "InVoIcE": invoice,
            "AmOuNt": "1",
            "CuRrEnCy": "SATS",
        }))
    else:
        header = "MPP request=\"{}\"".format(_encode_requirement({
            "MeThOdDeTaIlS": {"InVoIcE": invoice}
        }))
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _transport_response(402, headers={"WWW-Authenticate": header}),
            _transport_response(200, {"status": "paid"}),
        ],
    ) as transport:
        result = client.execute_detailed("GET", "https://buyer.test/start")

    assert result.response == {"status": "paid"}
    wallet.pay_invoice.assert_called_once_with(invoice)
    assert transport.call_count == 2


def test_lightning_policy_uses_integer_msats_not_public_float():
    parsed = parse_www_authenticate(
        f'L402 macaroon="{MACAROON}", invoice="{_signed_invoice(1000)}"'
    )
    parsed.amount = 999_999.0
    client = Payment402Client(
        policy=PaymentPolicy(max_spend_per_tx_usd=Decimal("0.001"))
    )

    client._enforce_policy(parsed, "https://buyer.test/start")
    assert client._estimate_usd_decimal(parsed) == Decimal("0.00065")


def test_exact_parser_private_canonical_flows_to_real_signer_and_verifier():
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    first = _exact_402()
    second = _transport_response(200, {"status": "paid"})
    real_atomic = client.evm_signer.generate_eip3009_payload_atomic

    with patch.object(
        client.evm_signer,
        "generate_eip3009_payload_atomic",
        wraps=real_atomic,
    ) as signer_call:
        with patch("ln_church_agent.client.requests.request", side_effect=[first, second]) as transport:
            result = client.execute_detailed("GET", "https://buyer.test/start")

    parsed = client._last_parsed_challenge
    assert result.response == {"status": "paid"}
    assert parsed._canonical_requirement is not None
    assert parsed._atomic_amount == "1000000"
    assert parsed._canonical_requirement["amount_atomic"] == "1000000"
    assert parsed._canonical_requirement["decimals"] == 6
    assert parsed._signer_requirement.atomic_amount == "1000000"
    signer_call.assert_called_once()
    signer_kwargs = signer_call.call_args.kwargs
    assert {
        key: signer_kwargs[key]
        for key in (
            "asset", "atomic_amount_str", "treasury_address", "chain_id",
            "token_address",
        )
    } == {
        "asset": "USDC",
        "atomic_amount_str": "1000000",
        "treasury_address": DESTINATION,
        "chain_id": 8453,
        "token_address": BASE_USDC,
    }
    assert signer_kwargs["valid_before"] == int(
        parsed._canonical_requirement["expires_at"]
    )
    assert signer_kwargs["requirement_hash"] == (
        parsed._canonical_requirement["requirement_hash"]
    )
    assert signer_kwargs["idempotency_key"] == (
        parsed._canonical_requirement["idempotency_key"]
    )
    assert signer_kwargs["now"] < signer_kwargs["valid_before"]
    sent_headers = transport.call_args_list[1].kwargs["headers"]
    signed_envelope = json.loads(
        base64.urlsafe_b64decode(
            sent_headers["PAYMENT-SIGNATURE"]
            + "=" * (-len(sent_headers["PAYMENT-SIGNATURE"]) % 4)
        )
    )
    assert signed_envelope["accepted"]["amount"] == "1000000"
    assert signed_envelope["payload"]["authorization"]["value"] == "1000000"


def test_exact_signer_cannot_mutate_approved_payto_during_callback():
    real_signer = LocalKeyAdapter(EVM_PRIVATE_KEY)

    class MutatingSigner:
        address = real_signer.address
        client = None

        def generate_eip3009_payload_atomic(self, **kwargs):
            parsed = self.client._last_parsed_challenge
            parsed._signer_requirement.pay_to = OTHER_ADDRESS
            mutated = dict(kwargs)
            mutated["treasury_address"] = OTHER_ADDRESS
            return real_signer.generate_eip3009_payload_atomic(**mutated)

    signer = MutatingSigner()
    evidence = _CaptureEvidence()
    client = Payment402Client(evm_signer=signer, evidence_repo=evidence)
    signer.client = client

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"unexpected": True})],
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert transport.call_count == 1
    assert evidence.records[-1].scheme == "exact"
    assert evidence.records[-1].asset == "USDC"
    assert evidence.records[-1].amount == 1.0


def test_exact_signer_cannot_mutate_approved_selected_option_during_callback():
    real_signer = LocalKeyAdapter(EVM_PRIVATE_KEY)

    class MutatingSigner:
        address = real_signer.address
        client = None

        def generate_eip3009_payload_atomic(self, **kwargs):
            parsed = self.client._last_parsed_challenge
            parsed.parameters["_raw_accepted"]["payTo"] = OTHER_ADDRESS
            return real_signer.generate_eip3009_payload_atomic(**kwargs)

    signer = MutatingSigner()
    client = Payment402Client(evm_signer=signer)
    signer.client = client

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"unexpected": True})],
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert transport.call_count == 1


def test_exact_signer_cannot_rewrite_the_approval_snapshot_during_callback():
    real_signer = LocalKeyAdapter(EVM_PRIVATE_KEY)

    class MutatingSigner:
        address = real_signer.address
        client = None

        def generate_eip3009_payload_atomic(self, **kwargs):
            parsed = self.client._last_parsed_challenge
            parsed._signer_requirement.pay_to = OTHER_ADDRESS
            parsed.parameters["_raw_accepted"]["payTo"] = OTHER_ADDRESS
            parsed.asset = "JPYC"
            parsed.amount = 2.0
            parsed._approved_signer_snapshot = (
                self.client._exact_signer_snapshot_json(parsed)
            )
            # Return a valid payload for the originally approved payment.  A
            # post-callback check that trusts the rewritten PrivateAttr would
            # otherwise allow the retry and mis-bind receipt metadata.
            return real_signer.generate_eip3009_payload_atomic(**kwargs)

    signer = MutatingSigner()
    evidence = _CaptureEvidence()
    client = Payment402Client(evm_signer=signer, evidence_repo=evidence)
    signer.client = client

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"unexpected": True})],
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert transport.call_count == 1
    assert evidence.records[-1].scheme == "exact"
    assert evidence.records[-1].asset == "USDC"
    assert evidence.records[-1].amount == 1.0


def test_exact_policy_ignores_tampered_public_float_amount():
    response = httpx.Response(
        402,
        headers={"PAYMENT-REQUIRED": _encode_requirement(_exact_payload())},
        request=httpx.Request("GET", "https://buyer.test/start"),
    )
    parsed = parse_challenge_from_response(response)
    parsed.amount = 999_999.0
    client = Payment402Client(policy=PaymentPolicy(max_spend_per_tx_usd=2.0))

    client._enforce_policy(parsed, "https://buyer.test/start")
    assert client._estimate_usd_decimal(parsed) == Decimal("1")


def test_invalid_evm_payto_0xabc_is_rejected_before_signer():
    signer = _RejectIfCalledSigner()
    client = Payment402Client(evm_signer=signer)
    context = ExecutionContext()
    payload = _exact_payload(accepted_overrides={"payTo": "0xabc"})

    with patch(
        "ln_church_agent.client.requests.request", return_value=_exact_402(payload)
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert signer.atomic_calls == 0
    assert transport.call_count == 1
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}


@pytest.mark.parametrize(
    "payload_mutator",
    [
        pytest.param(lambda p: p.update({"network": "eip155:137"}), id="outer-network"),
        pytest.param(lambda p: p.update({"chainId": 137}), id="outer-chain"),
        pytest.param(lambda p: p.update({"asset": "JPYC"}), id="outer-asset"),
        pytest.param(lambda p: p.update({"token_address": OTHER_ADDRESS}), id="outer-contract"),
        pytest.param(lambda p: p.update({"amount": "2"}), id="outer-amount"),
        pytest.param(lambda p: p.update({"destination": OTHER_ADDRESS}), id="outer-destination"),
        pytest.param(lambda p: p.update({"parameters": {"network": "eip155:137"}}), id="parameters-network"),
        pytest.param(lambda p: p.update({"parameters": {"chainId": 137}}), id="parameters-chain"),
        pytest.param(lambda p: p.update({"parameters": {"asset": "JPYC"}}), id="parameters-asset"),
        pytest.param(lambda p: p.update({"parameters": {"contract": OTHER_ADDRESS}}), id="parameters-contract"),
        pytest.param(lambda p: p.update({"parameters": {"amount": "2"}}), id="parameters-amount"),
        pytest.param(lambda p: p.update({"parameters": {"destination": OTHER_ADDRESS}}), id="parameters-destination"),
        pytest.param(lambda p: p["accepts"][0].update({"parameters": {"network": "eip155:137"}}), id="accepted-parameters-network"),
        pytest.param(lambda p: p["accepts"][0].update({"parameters": {"chainId": 137}}), id="accepted-parameters-chain"),
        pytest.param(lambda p: p["accepts"][0].update({"parameters": {"asset": "JPYC"}}), id="accepted-parameters-asset"),
        pytest.param(lambda p: p["accepts"][0].update({"parameters": {"contract": OTHER_ADDRESS}}), id="accepted-parameters-contract"),
        pytest.param(lambda p: p["accepts"][0].update({"parameters": {"amount": "2"}}), id="accepted-parameters-amount"),
        pytest.param(lambda p: p["accepts"][0].update({"parameters": {"destination": OTHER_ADDRESS}}), id="accepted-parameters-destination"),
    ],
)
def test_exact_metadata_contradiction_is_rejected_before_signer(payload_mutator):
    signer = _RejectIfCalledSigner()
    client = Payment402Client(evm_signer=signer)
    context = ExecutionContext()
    payload = _exact_payload()
    payload_mutator(payload)

    with patch(
        "ln_church_agent.client.requests.request", return_value=_exact_402(payload)
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert signer.atomic_calls == 0
    assert transport.call_count == 1
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}


def test_exact_without_accepts_fails_closed_before_signer():
    signer = _RejectIfCalledSigner()
    client = Payment402Client(evm_signer=signer)
    payload = {
        "scheme": "exact",
        "network": BASE_NETWORK,
        "asset": "USDC",
        "amount": "1",
        "payTo": DESTINATION,
        "resource": {},
    }

    with patch("ln_church_agent.client.requests.request", return_value=_exact_402(payload)):
        with pytest.raises(
            PaymentExecutionError,
            match="no complete canonical",
        ):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert signer.atomic_calls == 0


@pytest.mark.parametrize(
    "accepted",
    [
        pytest.param({"network": "eip155:999", "asset": BASE_USDC}, id="unknown-network"),
        pytest.param({"network": BASE_NETWORK, "asset": OTHER_ADDRESS}, id="unknown-contract"),
        pytest.param({"network": BASE_NETWORK, "asset": "0xabc"}, id="malformed-contract"),
    ],
)
def test_unknown_network_or_token_never_falls_back_to_chain_137(accepted):
    signer = _RejectIfCalledSigner()
    client = Payment402Client(evm_signer=signer)
    payload = _exact_payload(accepted_overrides=accepted)

    with patch("ln_church_agent.client.requests.request", return_value=_exact_402(payload)):
        with pytest.raises(
            PaymentExecutionError,
            match="Fail-Closed",
        ):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert signer.atomic_calls == 0


def test_invalid_configured_signer_address_is_rejected_before_signing():
    signer = _RejectIfCalledSigner()
    signer.address = "0xabc"
    client = Payment402Client(evm_signer=signer)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request", return_value=_exact_402()
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert signer.atomic_calls == 0
    assert transport.call_count == 1
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}


def test_local_key_adapter_real_eip3009_signature_verifies():
    adapter = LocalKeyAdapter(EVM_PRIVATE_KEY)
    payload = adapter.generate_eip3009_payload_atomic(
        asset="USDC",
        atomic_amount_str="1000000",
        treasury_address=DESTINATION,
        chain_id=8453,
        token_address=BASE_USDC,
    )

    recovered = validate_eip3009_payload(
        payload,
        expected_signer=adapter.address,
        chain_id=8453,
        token_address=BASE_USDC,
        asset="USDC",
        atomic_amount="1000000",
        pay_to=DESTINATION,
    )
    assert recovered.lower() == adapter.address.lower()


def _payload_signed_with_domain_change(field, value):
    adapter = LocalKeyAdapter(EVM_PRIVATE_KEY)
    payload = adapter.generate_eip3009_payload_atomic(
        "USDC", "1000000", DESTINATION, 8453, BASE_USDC
    )
    domain, types, message = build_eip3009_typed_data(
        chain_id=8453,
        token_address=BASE_USDC,
        asset="USDC",
        authorization=payload["authorization"],
    )
    domain[field] = value
    signable = encode_typed_data(
        domain_data=domain,
        message_types=types,
        message_data=message,
    )
    payload["signature"] = Account.from_key(EVM_PRIVATE_KEY).sign_message(signable).signature.hex()
    return payload


def _resign_eip3009_authorization(payload):
    domain, types, message = build_eip3009_typed_data(
        chain_id=8453,
        token_address=BASE_USDC,
        asset="USDC",
        authorization=payload["authorization"],
    )
    signable = encode_typed_data(
        domain_data=domain,
        message_types=types,
        message_data=message,
    )
    payload["signature"] = Account.from_key(EVM_PRIVATE_KEY).sign_message(
        signable
    ).signature.hex()


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda p: p["authorization"].update({"from": OTHER_ADDRESS}), id="from"),
        pytest.param(lambda p: p["authorization"].update({"to": OTHER_ADDRESS}), id="to"),
        pytest.param(lambda p: p["authorization"].update({"value": "999999"}), id="value"),
        pytest.param(lambda p: p["authorization"].update({"validAfter": str(int(time.time()) + 60)}), id="time-window"),
        pytest.param(lambda p: p["authorization"].update({"validBefore": str(int(time.time()) - 1)}), id="expired-valid-before"),
    ],
)
def test_eip3009_authorization_mutation_is_rejected(mutation):
    adapter = LocalKeyAdapter(EVM_PRIVATE_KEY)
    payload = adapter.generate_eip3009_payload_atomic(
        "USDC", "1000000", DESTINATION, 8453, BASE_USDC
    )
    mutation(payload)
    _resign_eip3009_authorization(payload)

    with pytest.raises(ValueError):
        validate_eip3009_payload(
            payload,
            expected_signer=adapter.address,
            chain_id=8453,
            token_address=BASE_USDC,
            asset="USDC",
            atomic_amount="1000000",
            pay_to=DESTINATION,
        )


@pytest.mark.parametrize(
    "nonce,resign",
    [
        pytest.param("0x01", False, id="invalid-format"),
        pytest.param("0x" + "22" * 32, False, id="typed-data-binding"),
    ],
)
def test_eip3009_nonce_format_and_signature_binding_are_enforced(nonce, resign):
    adapter = LocalKeyAdapter(EVM_PRIVATE_KEY)
    payload = adapter.generate_eip3009_payload_atomic(
        "USDC", "1000000", DESTINATION, 8453, BASE_USDC
    )
    payload["authorization"]["nonce"] = nonce
    if resign:
        _resign_eip3009_authorization(payload)

    with pytest.raises(ValueError):
        validate_eip3009_payload(
            payload,
            expected_signer=adapter.address,
            chain_id=8453,
            token_address=BASE_USDC,
            asset="USDC",
            atomic_amount="1000000",
            pay_to=DESTINATION,
        )


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param("0x12", id="format"),
        pytest.param("0x" + "11" * 65, id="wrong-signer"),
    ],
)
def test_eip3009_signature_mutation_is_rejected(signature):
    adapter = LocalKeyAdapter(EVM_PRIVATE_KEY)
    payload = adapter.generate_eip3009_payload_atomic(
        "USDC", "1000000", DESTINATION, 8453, BASE_USDC
    )
    payload["signature"] = signature

    with pytest.raises(ValueError):
        validate_eip3009_payload(
            payload,
            expected_signer=adapter.address,
            chain_id=8453,
            token_address=BASE_USDC,
            asset="USDC",
            atomic_amount="1000000",
            pay_to=DESTINATION,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("chainId", 137, id="domain-chain"),
        pytest.param("verifyingContract", OTHER_ADDRESS, id="domain-contract"),
        pytest.param("name", "Wrong Coin", id="domain-name"),
        pytest.param("version", "999", id="domain-version"),
    ],
)
def test_eip3009_wrong_signed_domain_is_rejected(field, value):
    payload = _payload_signed_with_domain_change(field, value)
    with pytest.raises(ValueError, match="signer|recovery"):
        validate_eip3009_payload(
            payload,
            expected_signer=EVM_SIGNER,
            chain_id=8453,
            token_address=BASE_USDC,
            asset="USDC",
            atomic_amount="1000000",
            pay_to=DESTINATION,
        )


def test_legacy_evm_signer_without_canonical_binding_fails_closed():
    backing = LocalKeyAdapter(EVM_PRIVATE_KEY)

    class LegacySigner:
        address = backing.address

        def generate_eip3009_payload(
            self, asset, human_amount, treasury_address, chain_id=137, token_address=None
        ):
            return backing.generate_eip3009_payload(
                asset, human_amount, treasury_address, chain_id, token_address
            )

        def execute_lnc_evm_relay_settlement(self, *args, **kwargs):
            raise AssertionError("wrong rail")

        def execute_lnc_evm_transfer_settlement(self, *args, **kwargs):
            raise AssertionError("wrong rail")

    client = Payment402Client(evm_signer=LegacySigner())
    context = ExecutionContext()
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"status": "paid"})],
    ) as transport:
        with pytest.raises(
            PaymentExecutionError,
            match="Legacy EVM signer",
        ):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert transport.call_count == 1
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0


def test_v1_16_1_evm_protocol_does_not_require_eip3009_generation():
    assert "generate_eip3009_payload" not in EVMSigner.__dict__


def test_exact_evm_signer_without_optional_generation_capability_fails_before_marker():
    class SettlementOnlySigner:
        address = EVM_SIGNER

        def execute_lnc_evm_relay_settlement(self, *args, **kwargs):
            raise AssertionError("settlement must not run")

        def execute_lnc_evm_transfer_settlement(self, *args, **kwargs):
            raise AssertionError("settlement must not run")

    context = ExecutionContext()
    client = Payment402Client(evm_signer=SettlementOnlySigner())
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"unexpected": True})],
    ) as transport:
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert "Ambiguous" not in str(caught.value)
    assert transport.call_count == 1
    assert context._ambiguous_reservations == {}
    assert set(context._payment_states.values()) == {"validation_failed"}


def test_public_execution_signatures_and_context_compatibility_bridge():
    expected_names = [
        "self",
        "method",
        "endpoint_path",
        "payload",
        "headers",
        "_current_hop",
        "_payment_retry_count",
        "context",
        "outcome_matcher",
        "_current_receipt",
    ]
    assert list(inspect.signature(Payment402Client.execute_detailed).parameters) == expected_names
    assert list(inspect.signature(Payment402Client.execute_detailed_async).parameters) == expected_names
    context = ExecutionContext(session_budget_restored=True)
    assert context.model_dump()["session_budget_restored"] is True
    assert context.session_budget_restored is True
    assert context._session_budget_restored is True
    repo = MagicMock()
    client = Payment402Client(evidence_repo=repo)
    client._restore_session_spend_from_evidence(context)
    repo.import_session_evidence.assert_not_called()
    assert NavigationGuardrailError.__bases__ == (Exception,)


def _svm_transaction(
    *,
    sender,
    destination_owner,
    amount=1_000_000,
    mint=MAINNET_USDC_MINT,
    fee_payer=None,
    unexpected_instruction=False,
    compute_limit=200_000,
    compute_price=1,
    duplicate_compute=False,
    duplicate_compute_price=False,
    malformed_compute=False,
    memo=None,
):
    from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
    from solders.hash import Hash
    from solders.instruction import Instruction
    from solders.keypair import Keypair
    from solders.message import MessageV0
    from solders.pubkey import Pubkey
    from solders.system_program import TransferParams, transfer
    from solders.transaction import VersionedTransaction
    from spl.token.constants import TOKEN_PROGRAM_ID
    from spl.token.instructions import (
        TransferCheckedParams,
        get_associated_token_address,
        transfer_checked,
    )

    payer = fee_payer or sender
    mint_key = Pubkey.from_string(mint) if isinstance(mint, str) else mint
    instructions = []
    if compute_limit is not None:
        instructions.append(set_compute_unit_limit(compute_limit))
    if compute_price is not None:
        instructions.append(set_compute_unit_price(compute_price))
    if duplicate_compute:
        instructions.append(set_compute_unit_limit(compute_limit or 200_000))
    if duplicate_compute_price:
        instructions.append(set_compute_unit_price(compute_price or 1))
    if malformed_compute:
        instructions.append(
            Instruction(
                Pubkey.from_string(
                    "ComputeBudget111111111111111111111111111111"
                ),
                b"\x02\x01",
                [],
            )
        )
    if unexpected_instruction:
        instructions.append(
            transfer(
                TransferParams(
                    from_pubkey=sender.pubkey(),
                    to_pubkey=Keypair().pubkey(),
                    lamports=1,
                )
            )
        )
    instructions.append(
        transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=get_associated_token_address(sender.pubkey(), mint_key),
                mint=mint_key,
                dest=get_associated_token_address(destination_owner.pubkey(), mint_key),
                owner=sender.pubkey(),
                amount=amount,
                decimals=6,
                signers=[],
            )
        )
    )
    # The normative x402 SVM client layout always has exactly one Memo after
    # TransferChecked.  Without an extra.memo challenge, the value is a
    # 16-byte random nonce encoded as 32 lowercase hex characters.
    memo_value = memo if memo is not None else "00" * 16
    instructions.append(
        Instruction(
            Pubkey.from_string(
                "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
            ),
            memo_value.encode("utf-8"),
            [],
        )
    )
    message = MessageV0.try_compile(
        payer.pubkey(), instructions, [], Hash.default()
    )
    keypairs = {str(sender.pubkey()): sender, str(payer.pubkey()): payer}
    signers = [keypairs[str(key)] for key in message.account_keys[: message.header.num_required_signatures]]
    transaction = VersionedTransaction(message, signers)
    return {"transaction": base64.b64encode(bytes(transaction)).decode()}


def _validate_svm(payload, *, sender, destination, fee_payer=None):
    from ln_church_agent.crypto.solana_svm import validate_svm_exact_payload

    payer = fee_payer or sender
    return validate_svm_exact_payload(
        payload,
        network=MAINNET_SVM,
        asset=MAINNET_USDC_MINT,
        amount="1000000",
        pay_to=str(destination.pubkey()),
        fee_payer=str(payer.pubkey()),
        signer_address=str(sender.pubkey()),
    )


def test_real_svm_transfer_checked_transaction_is_accepted():
    from solders.keypair import Keypair

    sender = Keypair()
    destination = Keypair()
    payload = _svm_transaction(sender=sender, destination_owner=destination)

    details = _validate_svm(payload, sender=sender, destination=destination)

    assert details["transfer"]["amount"] == "1000000"
    assert details["transfer"]["mint"] == MAINNET_USDC_MINT
    assert details["fee_payer"] == str(sender.pubkey())


@pytest.mark.parametrize(
    "compute_limit,compute_price",
    [(200_000, 1), (200_000, 1_000_000)],
)
def test_svm_compute_budget_within_fixed_bounds_is_accepted(
    compute_limit, compute_price
):
    from solders.keypair import Keypair

    sender = Keypair()
    destination = Keypair()
    payload = _svm_transaction(
        sender=sender,
        destination_owner=destination,
        compute_limit=compute_limit,
        compute_price=compute_price,
    )

    details = _validate_svm(payload, sender=sender, destination=destination)
    assert details["transfer"]["amount"] == "1000000"


def test_builtin_svm_adapter_emits_exact_bounded_compute_pair():
    from ln_church_agent.crypto.solana_svm import (
        COMPUTE_BUDGET_PROGRAM_ID_STR,
        LocalSvmAdapter,
        validate_svm_exact_payload,
    )
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction

    sender = Keypair()
    destination = Keypair()
    adapter = LocalSvmAdapter(private_key=str(sender))
    blockhash_response = MagicMock()
    blockhash_response.value.blockhash = Hash.default()
    rpc_client = MagicMock()
    rpc_client.get_latest_blockhash.return_value = blockhash_response

    with patch(
        "solana.rpc.api.Client",
        return_value=rpc_client,
    ):
        payload = adapter.generate_svm_exact_payload(
            MAINNET_SVM,
            MAINNET_USDC_MINT,
            "1000000",
            str(destination.pubkey()),
            adapter.address,
        )

    details = validate_svm_exact_payload(
        payload,
        network=MAINNET_SVM,
        asset=MAINNET_USDC_MINT,
        amount="1000000",
        pay_to=str(destination.pubkey()),
        fee_payer=adapter.address,
        signer_address=adapter.address,
    )
    transaction = VersionedTransaction.from_bytes(
        base64.b64decode(payload["transaction"])
    )
    account_keys = list(transaction.message.account_keys)
    compute_values = {}
    for instruction in transaction.message.instructions:
        if str(account_keys[instruction.program_id_index]) == COMPUTE_BUDGET_PROGRAM_ID_STR:
            data = bytes(instruction.data)
            compute_values[data[0]] = int.from_bytes(data[1:], "little")

    assert details["transfer"]["amount"] == "1000000"
    assert compute_values == {2: 200_000, 3: 1}


@pytest.mark.parametrize(
    "options",
    [
        {"compute_limit": 200_001, "compute_price": 1},
        {"compute_limit": 200_000, "compute_price": 1_000_001},
        {"compute_limit": 200_000, "compute_price": None},
        {"compute_limit": None, "compute_price": 1},
        {
            "compute_limit": 200_000,
            "compute_price": 1,
            "duplicate_compute": True,
        },
        {
            "compute_limit": 200_000,
            "compute_price": 1,
            "duplicate_compute_price": True,
        },
        {"malformed_compute": True},
    ],
    ids=[
        "oversize-limit",
        "oversize-price",
        "limit-only",
        "price-only",
        "duplicate-limit",
        "duplicate-price",
        "malformed-length",
    ],
)
def test_svm_compute_budget_outside_fixed_bounds_is_rejected(options):
    from solders.keypair import Keypair

    sender = Keypair()
    destination = Keypair()
    payload = _svm_transaction(
        sender=sender,
        destination_owner=destination,
        **options,
    )

    with pytest.raises(ValueError):
        _validate_svm(payload, sender=sender, destination=destination)


def test_svm_buyer_fee_payer_rejects_multi_sol_priority_fee_transaction():
    from solders.keypair import Keypair

    buyer = Keypair()
    destination = Keypair()
    payload = _svm_transaction(
        sender=buyer,
        destination_owner=destination,
        fee_payer=buyer,
        compute_limit=1_400_000,
        compute_price=5_000_000_000,
    )

    with pytest.raises(ValueError, match="compute-unit limit|priority fee"):
        _validate_svm(
            payload,
            sender=buyer,
            destination=destination,
            fee_payer=buyer,
        )


@pytest.mark.parametrize(
    "case",
    [
        "arbitrary-bytes",
        "wrong-destination",
        "wrong-amount",
        "wrong-mint",
        "wrong-fee-payer",
        "wrong-source",
        "unexpected-instruction",
    ],
)
def test_real_svm_transaction_mutation_is_rejected(case):
    from solders.keypair import Keypair

    sender = Keypair()
    destination = Keypair()
    expected_fee_payer = sender
    if case == "arbitrary-bytes":
        payload = {"transaction": base64.b64encode(b"attacker bytes").decode()}
    elif case == "wrong-destination":
        payload = _svm_transaction(sender=sender, destination_owner=Keypair())
    elif case == "wrong-amount":
        payload = _svm_transaction(
            sender=sender, destination_owner=destination, amount=999_999
        )
    elif case == "wrong-mint":
        payload = _svm_transaction(
            sender=sender,
            destination_owner=destination,
            mint=DEVNET_USDC_MINT,
        )
    elif case == "wrong-fee-payer":
        actual_fee_payer = Keypair()
        payload = _svm_transaction(
            sender=sender,
            destination_owner=destination,
            fee_payer=actual_fee_payer,
        )
    elif case == "wrong-source":
        payload = _svm_transaction(
            sender=Keypair(), destination_owner=destination
        )
    else:
        payload = _svm_transaction(
            sender=sender,
            destination_owner=destination,
            unexpected_instruction=True,
        )

    with pytest.raises(ValueError):
        _validate_svm(
            payload,
            sender=sender,
            destination=destination,
            fee_payer=expected_fee_payer,
        )


@pytest.mark.parametrize(
    "challenge_memo",
    [None, "provider-challenge-memo"],
    ids=["extra-memo-absent", "extra-memo-present"],
)
@pytest.mark.parametrize(
    "credential_state",
    ["absent", "configured"],
    ids=["without-svm-credentials", "with-svm-credentials"],
)
def test_client_fails_closed_canonical_svm_before_signer_or_paid_retry(
    challenge_memo, credential_state,
):
    from ln_church_agent.capabilities import get_capability_matrix
    from solders.keypair import Keypair

    capability = next(
        row
        for row in get_capability_matrix()
        if row["id"] == "x402_v2_exact_svm"
    )
    assert capability["execution_behavior"] == "halt"
    assert capability["default_recommended_action"] == "stop_safely"
    assert capability["requires_private_key"] is False
    assert capability["requires_payment_credential"] is False
    assert capability["can_execute_payment"] is False
    assert capability["can_execute_protected_action"] is False

    sender = Keypair()
    destination = Keypair()
    class StaticSvmSigner:
        address = str(sender.pubkey())

        def __init__(self):
            self.calls = 0

        def generate_svm_exact_payload(self, **kwargs):
            self.calls += 1
            raise AssertionError("SVM signer must not run in canonical mode")

    signer = StaticSvmSigner()
    context = ExecutionContext()
    client = Payment402Client()
    extra = {}
    if credential_state == "configured":
        client.svm_signer = signer
        extra["feePayer"] = str(sender.pubkey())
    if challenge_memo is not None:
        extra["memo"] = challenge_memo
    requirement = _exact_payload(
        accepted_overrides={
            "network": MAINNET_SVM,
            "asset": MAINNET_USDC_MINT,
            "payTo": str(destination.pubkey()),
            "extra": extra,
        }
    )

    initial_ledger_version = client.policy._session_ledger_version
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _exact_402(requirement),
            _transport_response(200, {"unexpected": True}),
        ],
    ) as transport, patch.object(
        client,
        "_reserve_session_budget",
        wraps=client._reserve_session_budget,
    ) as reserve_budget, patch.object(
        client,
        "_release_session_budget",
        wraps=client._release_session_budget,
    ) as release_budget, patch.object(
        client,
        "_confirm_session_budget",
        wraps=client._confirm_session_budget,
    ) as confirm_budget, patch.object(
        client,
        "_process_payment",
        wraps=client._process_payment,
    ) as process_payment, patch(
        "solana.rpc.api.Client.get_latest_blockhash"
    ) as svm_rpc:
        with pytest.raises(
            PaymentExecutionError,
            match="recent-blockhash validity.*canonical expires_at",
        ) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert signer.calls == 0
    reserve_budget.assert_not_called()
    release_budget.assert_not_called()
    confirm_budget.assert_not_called()
    process_payment.assert_not_called()
    svm_rpc.assert_not_called()
    assert transport.call_count == 1
    assert "Ambiguous" not in str(caught.value)
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}
    assert context._budget_reservations == {}
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == 0
    assert client.policy._session_budget_operation_journal == {}
    assert client.policy._session_budget_operation_versions == {}
    assert client.policy._session_ledger_version == initial_ledger_version


def test_client_rejects_invalid_custom_evm_signer_output_before_paid_retry():
    class InvalidEvmSigner:
        address = EVM_SIGNER

        def __init__(self):
            self.calls = 0

        def generate_eip3009_payload_atomic(self, **kwargs):
            self.calls += 1
            return {
                "authorization": {
                    "from": self.address,
                    "to": OTHER_ADDRESS,
                    "value": kwargs["atomic_amount_str"],
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) + 300),
                    "nonce": "0x" + "11" * 32,
                },
                "signature": "0x" + "00" * 65,
            }

    signer = InvalidEvmSigner()
    evidence = _CaptureEvidence()
    context = ExecutionContext()
    client = Payment402Client(evm_signer=signer, evidence_repo=evidence)
    from ln_church_agent.crypto.evm import validate_eip3009_payload as real_validator

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"unexpected": True})],
    ) as transport, patch(
        "ln_church_agent.client.validate_eip3009_payload",
        wraps=real_validator,
    ) as validator:
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert signer.calls == 1
    validator.assert_called_once()
    assert transport.call_count == 1
    assert "Ambiguous" not in str(caught.value)
    assert list(_exception_chain(caught.value)) == [caught.value]
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0
    assert all(record.session_spend_delta_usd in (None, 0) for record in evidence.records)

    with patch(
        "ln_church_agent.client.requests.request", return_value=_exact_402()
    ) as retry_transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )
    assert signer.calls == 2
    assert retry_transport.call_count == 1


def test_client_fails_closed_svm_before_custom_signer_output_or_reserve():
    from solders.keypair import Keypair

    sender = Keypair()
    destination = Keypair()
    class UntrustedSvmSigner:
        address = str(sender.pubkey())

        def __init__(self):
            self.calls = 0

        def generate_svm_exact_payload(self, **kwargs):
            self.calls += 1
            raise AssertionError("custom SVM signer must not run")

    signer = UntrustedSvmSigner()
    evidence = _CaptureEvidence()
    context = ExecutionContext()
    client = Payment402Client(evidence_repo=evidence)
    client.svm_signer = signer
    requirement = _exact_payload(
        accepted_overrides={
            "network": MAINNET_SVM,
            "asset": MAINNET_USDC_MINT,
            "payTo": str(destination.pubkey()),
            "extra": {"feePayer": str(sender.pubkey())},
        }
    )

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _exact_402(requirement),
            _transport_response(200, {"unexpected": True}),
        ],
    ) as transport:
        with pytest.raises(
            PaymentExecutionError, match="canonical SVM exact auto-payment"
        ) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert signer.calls == 0
    assert transport.call_count == 1
    assert "Ambiguous" not in str(caught.value)
    assert list(_exception_chain(caught.value)) == [caught.value]
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0
    assert all(record.session_spend_delta_usd in (None, 0) for record in evidence.records)

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_exact_402(requirement),
    ) as retry_transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )
    assert signer.calls == 0
    assert retry_transport.call_count == 1


def test_async_client_rejects_invalid_evm_signer_output_without_reserve():
    class InvalidEvmSigner:
        address = EVM_SIGNER

        def __init__(self):
            self.calls = 0

        def generate_eip3009_payload_atomic(self, **kwargs):
            self.calls += 1
            return {
                "authorization": {
                    "from": self.address,
                    "to": OTHER_ADDRESS,
                    "value": kwargs["atomic_amount_str"],
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) + 300),
                    "nonce": "0x" + "11" * 32,
                },
                "signature": "0x" + "00" * 65,
            }

    async def run():
        signer = InvalidEvmSigner()
        evidence = _CaptureEvidence()
        context = ExecutionContext()
        client = Payment402Client(evm_signer=signer, evidence_repo=evidence)
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _exact_402(),
                _transport_response(200, {"unexpected": True}),
            ]
        )

        with pytest.raises(PaymentExecutionError) as caught:
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )

        assert signer.calls == 1
        assert client._async_client.request.call_count == 1
        assert "Ambiguous" not in str(caught.value)
        assert list(_exception_chain(caught.value)) == [caught.value]
        assert set(context._payment_states.values()) == {"validation_failed"}
        assert context._ambiguous_reservations == {}
        assert client.policy._session_spent_usd == 0
        assert all(
            record.session_spend_delta_usd in (None, 0)
            for record in evidence.records
        )

        client._async_client.request = AsyncMock(return_value=_exact_402())
        with pytest.raises(PaymentExecutionError):
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )
        assert signer.calls == 2
        assert client._async_client.request.call_count == 1

    asyncio.run(run())


@pytest.mark.parametrize(
    "credential_state",
    ["absent", "configured"],
    ids=["without-svm-credentials", "with-svm-credentials"],
)
def test_async_client_fails_closed_svm_before_signer_or_reserve(
    credential_state,
):
    from solders.keypair import Keypair

    sender = Keypair()
    destination = Keypair()
    class UntrustedSvmSigner:
        address = str(sender.pubkey())

        def __init__(self):
            self.calls = 0

        def generate_svm_exact_payload(self, **kwargs):
            self.calls += 1
            raise AssertionError("custom SVM signer must not run")

    async def run():
        signer = UntrustedSvmSigner()
        context = ExecutionContext()
        client = Payment402Client()
        extra = {}
        if credential_state == "configured":
            client.svm_signer = signer
            extra["feePayer"] = str(sender.pubkey())
        requirement = _exact_payload(
            accepted_overrides={
                "network": MAINNET_SVM,
                "asset": MAINNET_USDC_MINT,
                "payTo": str(destination.pubkey()),
                "extra": extra,
            }
        )
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _exact_402(requirement),
                _transport_response(200, {"unexpected": True}),
            ]
        )

        initial_ledger_version = client.policy._session_ledger_version
        with patch.object(
            client,
            "_reserve_session_budget",
            wraps=client._reserve_session_budget,
        ) as reserve_budget, patch.object(
            client,
            "_release_session_budget",
            wraps=client._release_session_budget,
        ) as release_budget, patch.object(
            client,
            "_confirm_session_budget",
            wraps=client._confirm_session_budget,
        ) as confirm_budget, patch.object(
            client,
            "_process_payment",
            wraps=client._process_payment,
        ) as process_payment, patch(
            "solana.rpc.api.Client.get_latest_blockhash"
        ) as svm_rpc:
            with pytest.raises(
                PaymentExecutionError, match="canonical SVM exact auto-payment"
            ) as caught:
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )

        assert signer.calls == 0
        reserve_budget.assert_not_called()
        release_budget.assert_not_called()
        confirm_budget.assert_not_called()
        process_payment.assert_not_called()
        svm_rpc.assert_not_called()
        assert client._async_client.request.call_count == 1
        assert "Ambiguous" not in str(caught.value)
        assert list(_exception_chain(caught.value)) == [caught.value]
        assert set(context._payment_states.values()) == {"validation_failed"}
        assert context._ambiguous_reservations == {}
        assert context._budget_reservations == {}
        assert client.policy._session_spent_usd == 0
        assert client.policy._session_reserved_usd == 0
        assert client.policy._session_budget_operation_journal == {}
        assert client.policy._session_budget_operation_versions == {}
        assert client.policy._session_ledger_version == initial_ledger_version

    asyncio.run(run())


def test_async_disabled_svm_never_occupies_budget_needed_by_other_operation():
    """A halted SVM lane must not transiently block a valid shared-session buy."""
    from solders.keypair import Keypair

    destination = Keypair()
    policy = PaymentPolicy(
        max_spend_per_tx_usd=2.0,
        max_spend_per_session_usd=1.2,
    )
    svm_client = Payment402Client(policy=policy)
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    l402_client = Payment402Client(policy=policy, ln_adapter=wallet)
    svm_context = ExecutionContext(session_id="shared-svm-preflight-session")
    l402_context = ExecutionContext(session_id="shared-svm-preflight-session")

    svm_requirement = _exact_payload(
        accepted_overrides={
            "network": MAINNET_SVM,
            "asset": MAINNET_USDC_MINT,
            "payTo": str(destination.pubkey()),
            "extra": {},
        }
    )
    svm_client._async_client = MagicMock()
    svm_client._async_client.request = AsyncMock(
        return_value=_exact_402(svm_requirement)
    )
    l402_client._async_client = MagicMock()
    l402_client._async_client.request = AsyncMock(
        side_effect=[
            _l402_402(msats=1_000_000),
            _transport_response(200, {"result": "other-operation-paid"}),
        ]
    )

    # This blocker makes the pre-fix reserve -> process window deterministic.
    # The fixed high-level SVM path must never reach it.
    process_entered = threading.Event()
    allow_process_to_finish = threading.Event()
    original_process = svm_client._process_payment

    def blocking_process(*args, **kwargs):
        process_entered.set()
        assert allow_process_to_finish.wait(timeout=5)
        return original_process(*args, **kwargs)

    async def run():
        with patch.object(
            svm_client,
            "_reserve_session_budget",
            wraps=svm_client._reserve_session_budget,
        ) as reserve_budget, patch.object(
            svm_client,
            "_release_session_budget",
            wraps=svm_client._release_session_budget,
        ) as release_budget, patch.object(
            svm_client,
            "_confirm_session_budget",
            wraps=svm_client._confirm_session_budget,
        ) as confirm_budget, patch.object(
            svm_client,
            "_process_payment",
            side_effect=blocking_process,
        ) as process_payment:
            svm_task = asyncio.create_task(
                svm_client.execute_detailed_async(
                    "GET",
                    "https://buyer.test/start",
                    headers={"Idempotency-Key": "disabled-svm-operation"},
                    context=svm_context,
                )
            )
            for _ in range(200):
                if svm_task.done() or process_entered.is_set():
                    break
                await asyncio.sleep(0.005)

            other_result = None
            other_error = None
            try:
                other_result = await l402_client.execute_detailed_async(
                    "GET",
                    "https://buyer.test/start",
                    headers={"Idempotency-Key": "valid-l402-operation"},
                    context=l402_context,
                )
            except Exception as caught:
                other_error = caught
            finally:
                allow_process_to_finish.set()

            with pytest.raises(
                PaymentExecutionError,
                match="canonical SVM exact auto-payment",
            ):
                await svm_task
            if other_error is not None:
                raise other_error

            reserve_budget.assert_not_called()
            release_budget.assert_not_called()
            confirm_budget.assert_not_called()
            process_payment.assert_not_called()
            assert other_result is not None
            return other_result

    result = asyncio.run(run())

    assert result.response == {"result": "other-operation-paid"}
    wallet.pay_invoice.assert_called_once()
    assert svm_client._async_client.request.call_count == 1
    assert l402_client._async_client.request.call_count == 2
    assert policy._session_reserved_usd == 0
    assert policy._session_spent_usd == pytest.approx(0.65)
    assert svm_context._budget_reservations == {}
    assert svm_context._ambiguous_reservations == {}
    svm_operation = next(iter(svm_context._payment_states))
    budget_journal = policy._session_budget_operation_journal[
        "shared-svm-preflight-session"
    ]
    assert svm_operation not in budget_journal
    assert len(budget_journal) == 1
    assert next(iter(budget_journal.values()))[0] == "confirmed"


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_signer_exception_before_irreversible_marker_is_retryable_and_secret_free(
    async_mode,
):
    secret = "DUMMY_SIGNER_SECRET_BEFORE_IRREVERSIBLE"

    class RaisingSigner:
        address = EVM_SIGNER

        def __init__(self):
            self.calls = 0

        def generate_eip3009_payload_atomic(self, **kwargs):
            self.calls += 1
            raise RuntimeError(secret)

    signer = RaisingSigner()
    evidence = _CaptureEvidence()
    context = ExecutionContext()
    client = Payment402Client(evm_signer=signer, evidence_repo=evidence)

    if async_mode:
        async def run_once():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(return_value=_exact_402())
            with pytest.raises(RuntimeError) as caught:
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )
            return caught.value, client._async_client.request.call_count

        error, transport_calls = asyncio.run(run_once())
    else:
        with patch(
            "ln_church_agent.client.requests.request", return_value=_exact_402()
        ) as transport:
            with pytest.raises(RuntimeError) as caught:
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
        error, transport_calls = caught.value, transport.call_count

    assert signer.calls == 1
    assert transport_calls == 1
    assert secret not in str(error)
    assert secret not in repr(error)
    assert list(_exception_chain(error)) == [error]
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0
    assert all(record.session_spend_delta_usd in (None, 0) for record in evidence.records)

    if async_mode:
        _, retry_calls = asyncio.run(run_once())
    else:
        with patch(
            "ln_church_agent.client.requests.request", return_value=_exact_402()
        ) as retry_transport:
            with pytest.raises(RuntimeError):
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
        retry_calls = retry_transport.call_count
    assert signer.calls == 2
    assert retry_calls == 1


SENSITIVE_HEADERS = {
    "Authorization": "Bearer original",
    "Proxy-Authorization": "proxy-secret",
    "Cookie": "sid=secret",
    "Set-Cookie": "sid=response-secret",
    "X-Api-Key": "api-secret",
    "Client-Secret": "client-secret",
    "Refresh-Token": "refresh-token-secret",
    "Grant-Token": "grant-secret",
    "GrantToken": "camel-grant-secret",
    "Faucet-Proof": "faucet-secret",
    "FaucetProof": "camel-faucet-secret",
    "Payment-Authorization": "payment-secret",
    "PaymentAuthorization": "camel-payment-secret",
    "L402-Credential": "l402-secret",
    "MPP-Token": "mpp-secret",
    "Macaroon": "macaroon-secret",
    "Preimage": "preimage-secret",
    "X-Internal-Secret": "internal-secret",
    "X-LN-Result-Handle": "result-handle-secret",
    "X-LN-Request-Hash": "request-hash-secret",
    "X-Probe-Token": "probe-token-secret",
    "X-Access-Token": "access-token-secret",
    "X_Access_Token": "underscore-access-token-secret",
    "Private-Key": "private-key-secret",
    "Signature": "sig-secret",
    "sIgNaTuRe-InPuT": "sig-input-secret",
    "DPoP": "dpop-secret",
}


def _assert_sensitive_header_families_absent(headers):
    normalized = {
        key.lower().replace("_", "-"): value for key, value in headers.items()
    }
    for original_name, original_value in SENSITIVE_HEADERS.items():
        key = original_name.lower().replace("_", "-")
        assert key not in normalized


def _nested_secret_payload():
    return {
        "safe": "keep",
        "business_data": "private-original-value",
        "nested": [
            {
                "paymentOverride": "drop",
                "paymentSignature": "drop",
                "payment-signature": "drop",
                "child": {
                    "proof": "drop",
                    "client_secret": "drop",
                    "wallet_private_key": "drop",
                    "service_api_key": "drop",
                    "safeChild": "keep-child",
                },
            },
            {
                "token": "drop",
                "interop_token": "drop",
                "interopToken": "drop",
                "verify_token": "drop",
                "verifyToken": "drop",
                "password": "drop",
                "credential": "drop",
                "bearer": "drop",
                "refresh_token": "drop",
                "accessToken": "drop",
                "privateToken": "drop",
                "grantToken": "drop",
                "l402_macaroon": "drop",
                "payment_preimage": "drop",
                "raw_authorization": "drop",
                "visible": "keep-visible",
            },
        ],
    }


def test_cross_origin_redirect_strips_real_second_request_headers_and_params():
    client = Payment402Client()
    context = ExecutionContext(hints={"allowed_hosts": ["dest.test"]})
    first = _transport_response(
        302,
        headers={"Location": "https://dest.test/next"},
        url="https://source.test/start",
    )
    second = _transport_response(200, {"status": "ok"}, url="https://dest.test/next")
    headers = {**SENSITIVE_HEADERS, "X-Safe": "keep"}

    with patch(
        "ln_church_agent.client.requests.request", side_effect=[first, second]
    ) as transport:
        result = client.execute_detailed(
            "GET",
            "https://source.test/start",
            payload=_nested_secret_payload(),
            headers=headers,
            context=context,
        )

    assert result.response == {"status": "ok"}
    second_call = transport.call_args_list[1]
    _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
    assert second_call.kwargs["headers"]["X-Safe"] == "keep"
    assert second_call.kwargs["params"] is None
    assert second_call.kwargs["headers"]["Host"] == "dest.test"
    assert urlparse(second_call.args[1]).path == "/next"


def test_same_origin_new_path_rotates_payment_credentials_before_second_request():
    client = Payment402Client()
    first = _transport_response(
        302,
        headers={"Location": "/other?step=2"},
        url="https://source.test/start",
    )
    second = _transport_response(200, {"status": "ok"}, url="https://source.test/other")

    with patch(
        "ln_church_agent.client.requests.request", side_effect=[first, second]
    ) as transport:
        client.execute_detailed(
            "GET",
            "https://source.test/start",
            payload=_nested_secret_payload(),
            headers={**SENSITIVE_HEADERS, "X-Safe": "keep"},
        )

    second_call = transport.call_args_list[1]
    second_headers = second_call.kwargs["headers"]
    _assert_sensitive_header_families_absent(second_headers)
    assert second_headers["X-Safe"] == "keep"
    expected_params = {
        "safe": "keep",
        "business_data": "private-original-value",
        "nested": [
            {"child": {"safeChild": "keep-child"}},
            {"visible": "keep-visible"},
        ],
    }
    assert second_call.kwargs["params"] is None
    expected_wire = client._final_wire_url(
        "GET", "https://source.test/other?step=2", expected_params
    )
    assert second_call.args[1] == expected_wire.replace(
        "https://source.test", "https://93.184.216.34"
    )


@pytest.mark.parametrize(
    "destination,expected_params",
    [
        (
            "https://source.test:443/next",
            {
                "safe": "keep",
                "business_data": "private-original-value",
                "nested": [
                    {"child": {"safeChild": "keep-child"}},
                    {"visible": "keep-visible"},
                ],
            },
        ),
        ("https://source.test:8443/next", {}),
    ],
    ids=["explicit-default-port-same-origin", "alternate-port-cross-origin"],
)
def test_origin_comparison_uses_effective_port_without_weakening_strict_policy(
    destination, expected_params
):
    destination_netloc = destination.split("/", 3)[2]
    client = Payment402Client(
        policy=PaymentPolicy(
            allowed_hosts=["source.test", destination_netloc]
        )
    )
    context = ExecutionContext(
        hints={"allowed_hosts": [destination_netloc]}
    )
    first = _transport_response(
        302,
        headers={"Location": destination},
        url="https://source.test/start",
    )
    second = _transport_response(200, {"status": "ok"}, url=destination)

    with patch(
        "ln_church_agent.client.requests.request", side_effect=[first, second]
    ) as transport:
        result = client.execute_detailed(
            "GET",
            "https://source.test/start",
            payload=_nested_secret_payload(),
            headers={**SENSITIVE_HEADERS, "X-Safe": "keep"},
            context=context,
        )

    assert result.response == {"status": "ok"}
    second_call = transport.call_args_list[1]
    _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
    assert second_call.kwargs["params"] is None
    expected_wire = client._final_wire_url("GET", destination, expected_params)
    assert urlparse(second_call.args[1]).path == urlparse(expected_wire).path
    assert urlparse(second_call.args[1]).query == urlparse(expected_wire).query


def test_hateoas_strips_original_and_suggested_nested_secrets_at_transport():
    client = Payment402Client(auto_navigate=True)
    first = _transport_response(
        400,
        {
            "next_action": {
                "method": "GET",
                "url": "/next",
                "instruction_for_agent": "Continue safely",
                "suggested_headers": {
                    **SENSITIVE_HEADERS,
                    "X-Suggested-Safe": "keep-suggested",
                },
                "suggested_payload": {
                    "suggested": [
                        {"paymentOverride": "drop"},
                        {"proof": "drop", "safeSuggested": "keep"},
                    ]
                },
            }
        },
        url="https://source.test/start",
    )
    second = _transport_response(200, {"status": "ok"}, url="https://source.test/next")

    with patch(
        "ln_church_agent.client.requests.request", side_effect=[first, second]
    ) as transport:
        result = client.execute_detailed(
            "GET",
            "https://source.test/start",
            payload=_nested_secret_payload(),
            headers={**SENSITIVE_HEADERS, "X-Safe": "keep"},
        )

    assert result.response == {"status": "ok"}
    second_call = transport.call_args_list[1]
    _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
    assert second_call.kwargs["headers"]["X-Safe"] == "keep"
    assert second_call.kwargs["headers"]["X-Suggested-Safe"] == "keep-suggested"
    expected_params = {
        "safe": "keep",
        "business_data": "private-original-value",
        "nested": [
            {"child": {"safeChild": "keep-child"}},
            {"visible": "keep-visible"},
        ],
        "suggested": [{}, {"safeSuggested": "keep"}],
    }
    assert second_call.kwargs["params"] is None
    expected_wire = client._final_wire_url(
        "GET", "https://source.test/next", expected_params
    )
    assert second_call.args[1] == expected_wire.replace(
        "https://source.test", "https://93.184.216.34"
    )


def test_cross_origin_hateoas_drops_original_payload_and_uses_sanitized_suggestion():
    client = Payment402Client(auto_navigate=True)
    context = ExecutionContext(hints={"allowed_hosts": ["dest.test"]})
    first = _transport_response(
        400,
        {
            "next_action": {
                "method": "GET",
                "url": "https://dest.test/next",
                "instruction_for_agent": "Continue cross-origin safely",
                "suggested_headers": {
                    **SENSITIVE_HEADERS,
                    "X-Suggested-Safe": "keep",
                },
                "suggested_payload": {
                    "safe_suggested": "keep",
                    "nested": [{
                        "client_secret": "drop",
                        "paymentSignature": "drop",
                        "wallet_private_key": "drop",
                        "service-api-key": "drop",
                        "l402Macaroon": "drop",
                        "payment preimage": "drop",
                        "rawAuthorization": "drop",
                        "visible": "keep",
                    }],
                },
            }
        },
        url="https://source.test/start",
    )
    second = _transport_response(200, {"status": "ok"}, url="https://dest.test/next")

    with patch(
        "ln_church_agent.client.requests.request", side_effect=[first, second]
    ) as transport:
        result = client.execute_detailed(
            "GET",
            "https://source.test/start",
            payload={"business_data": "private-original-value"},
            headers={**SENSITIVE_HEADERS, "X-Original-Safe": "keep"},
            context=context,
        )

    assert result.response == {"status": "ok"}
    second_call = transport.call_args_list[1]
    _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
    assert second_call.kwargs["headers"]["X-Original-Safe"] == "keep"
    assert second_call.kwargs["headers"]["X-Suggested-Safe"] == "keep"
    expected_params = {
        "safe_suggested": "keep",
        "nested": [{"visible": "keep"}],
    }
    assert second_call.kwargs["params"] is None
    expected_wire = client._final_wire_url(
        "GET", "https://dest.test/next", expected_params
    )
    assert second_call.args[1] == expected_wire.replace(
        "https://dest.test", "https://93.184.216.34"
    )


def test_external_observation_redacts_nested_secrets_but_preserves_public_evidence():
    client = LnChurchClient(private_key=EVM_PRIVATE_KEY)
    evidence = {
        "proof_reference": "public-ref",
        "payment_hash": "public-hash",
        "payment_receipt_present": True,
        "authorization_scheme": "eip3009",
        "token_address": BASE_USDC,
        "credential_fingerprint": "public-fingerprint",
        "payment_response_presence": True,
        "nested": [
            {
                "password": "drop",
                "paymentSignature": "drop",
                "wallet_private_key": "drop",
                "service_api_key": "drop",
                "l402_macaroon": "drop",
                "payment_preimage": "drop",
                "raw_authorization": "drop",
                "visible": "keep",
            },
            (
                {
                    "interop_token": "drop",
                    "accessToken": "drop",
                    "credential": "drop",
                    "proof_reference": "nested-ref",
                },
                {
                    "verifyToken": "drop",
                    "client_secret": "drop",
                    "refreshToken": "drop",
                    "bearer": "drop",
                    "grantToken": "drop",
                },
            ),
        ],
    }

    with patch.object(client, "execute_request", return_value={"ok": True}) as send:
        result = client.submit_external_observation(
            "https://surface.test", evidence=evidence
        )

    assert result == {"ok": True}
    sent = send.call_args.kwargs["payload"]["evidence"]
    assert sent == {
        "proof_reference": "public-ref",
        "payment_hash": "public-hash",
        "payment_receipt_present": True,
        "authorization_scheme": "eip3009",
        "token_address": BASE_USDC,
        "credential_fingerprint": "public-fingerprint",
        "payment_response_presence": True,
        "nested": [
            {"visible": "keep"},
            ({"proof_reference": "nested-ref"}, {}),
        ],
    }


def test_external_observation_async_redacts_secret_families_in_sent_payload():
    async def run():
        client = LnChurchClient(private_key=EVM_PRIVATE_KEY)
        evidence = {
            "nested": [
                {
                    "paymentSignature": "drop",
                    "wallet-private-key": "drop",
                    "service api key": "drop",
                    "l402Macaroon": "drop",
                    "payment_preimage": "drop",
                    "rawAuthorization": "drop",
                    "payment_hash": "public-hash",
                    "proof_reference": "public-ref",
                    "token_address": BASE_USDC,
                    "authorization_scheme": "eip3009",
                }
            ]
        }
        with patch.object(
            client, "execute_request_async", new=AsyncMock(return_value={"ok": True})
        ) as send:
            result = await client.submit_external_observation_async(
                "https://surface.test", evidence=evidence
            )
        return result, send.call_args.kwargs["payload"]["evidence"]

    result, sent = asyncio.run(run())
    assert result == {"ok": True}
    assert sent == {
        "nested": [{
            "payment_hash": "public-hash",
            "proof_reference": "public-ref",
            "token_address": BASE_USDC,
            "authorization_scheme": "eip3009",
        }]
    }


def test_local_blocked_host_policy_wins_over_hints_and_allow_unsafe_navigation():
    policy = PaymentPolicy(blocked_hosts=["blocked.test"])
    client = Payment402Client(
        policy=policy,
        allow_unsafe_navigate=True,
        auto_navigate=True,
    )
    context = ExecutionContext(hints={"allowed_hosts": ["blocked.test"]})
    redirect = _transport_response(
        302,
        headers={"Location": "https://blocked.test/next"},
        url="https://source.test/start",
    )

    with patch(
        "ln_church_agent.client.requests.request", return_value=redirect
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match="blocked_hosts"):
            client.execute_detailed(
                "GET", "https://source.test/start", context=context
            )

    assert transport.call_count == 1


def test_local_allowed_host_policy_cannot_be_extended_by_hints():
    policy = PaymentPolicy(allowed_hosts=["source.test"])
    client = Payment402Client(policy=policy, allow_unsafe_navigate=True)
    context = ExecutionContext(hints={"allowed_hosts": ["dest.test"]})
    redirect = _transport_response(
        302,
        headers={"Location": "https://dest.test/next"},
        url="https://source.test/start",
    )

    with patch(
        "ln_church_agent.client.requests.request", return_value=redirect
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match="not in allowed_hosts"):
            client.execute_detailed(
                "GET", "https://source.test/start", context=context
            )

    assert transport.call_count == 1


@pytest.mark.parametrize(
    "allowed_hosts,url,allowed",
    [
        (["TRUSTED.COM"], "https://trusted.com/path", True),
        (["trusted.com"], "https://trusted.com:443/path", False),
        (["trusted.com:443"], "https://trusted.com:443/path", True),
        (["trusted.com"], "https://trusted.com:8443/path", False),
        (["TRUSTED.COM:8443"], "https://trusted.com:8443/path", True),
    ],
)
def test_strict_netloc_allowed_hosts_sync(allowed_hosts, url, allowed):
    client = Payment402Client(policy=PaymentPolicy(allowed_hosts=allowed_hosts))
    response = _transport_response(200, {"status": "ok"}, url=url)

    with patch(
        "ln_church_agent.client.requests.request", return_value=response
    ) as transport:
        if allowed:
            assert client.execute_detailed("GET", url).response == {"status": "ok"}
            assert transport.call_count == 1
        else:
            with pytest.raises(NavigationGuardrailError) as caught:
                client.execute_detailed("GET", url)
            assert isinstance(caught.value, NavigationGuardrailError)
            assert transport.call_count == 0


@pytest.mark.parametrize(
    "blocked_hosts,url,blocked",
    [
        (["TRUSTED.COM"], "https://trusted.com/path", True),
        (["trusted.com"], "https://trusted.com:443/path", False),
        (["trusted.com:443"], "https://trusted.com:443/path", True),
        (["trusted.com:8443"], "https://trusted.com:8443/path", True),
    ],
)
def test_strict_netloc_blocked_hosts_sync(blocked_hosts, url, blocked):
    client = Payment402Client(policy=PaymentPolicy(blocked_hosts=blocked_hosts))
    response = _transport_response(200, {"status": "ok"}, url=url)

    with patch(
        "ln_church_agent.client.requests.request", return_value=response
    ) as transport:
        if blocked:
            with pytest.raises(NavigationGuardrailError) as caught:
                client.execute_detailed("GET", url)
            assert isinstance(caught.value, NavigationGuardrailError)
            assert transport.call_count == 0
        else:
            assert client.execute_detailed("GET", url).response == {"status": "ok"}
            assert transport.call_count == 1


@pytest.mark.parametrize(
    "policy_kwargs,url,allowed",
    [
        ({"allowed_hosts": ["TRUSTED.COM"]}, "https://trusted.com/path", True),
        ({"allowed_hosts": ["trusted.com"]}, "https://trusted.com:443/path", False),
        ({"allowed_hosts": ["trusted.com:443"]}, "https://trusted.com:443/path", True),
        ({"allowed_hosts": ["trusted.com"]}, "https://trusted.com:8443/path", False),
        ({"allowed_hosts": ["TRUSTED.COM:8443"]}, "https://trusted.com:8443/path", True),
        ({"blocked_hosts": ["TRUSTED.COM"]}, "https://trusted.com/path", False),
        ({"blocked_hosts": ["trusted.com"]}, "https://trusted.com:443/path", True),
        ({"blocked_hosts": ["trusted.com:443"]}, "https://trusted.com:443/path", False),
        ({"blocked_hosts": ["trusted.com:8443"]}, "https://trusted.com:8443/path", False),
    ],
    ids=[
        "allowed-implicit-case",
        "allowed-host-does-not-match-explicit-443",
        "allowed-explicit-443",
        "allowed-host-does-not-match-8443",
        "allowed-explicit-8443-case",
        "blocked-implicit-case",
        "blocked-host-does-not-match-explicit-443",
        "blocked-explicit-443",
        "blocked-explicit-8443",
    ],
)
def test_strict_netloc_allowed_and_blocked_hosts_async(
    policy_kwargs, url, allowed
):
    async def run():
        client = Payment402Client(policy=PaymentPolicy(**policy_kwargs))
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            return_value=_transport_response(
                200, {"status": "ok"}, url=url
            )
        )
        if allowed:
            result = await client.execute_detailed_async("GET", url)
            assert result.response == {"status": "ok"}
            assert client._async_client.request.call_count == 1
        else:
            with pytest.raises(NavigationGuardrailError) as caught:
                await client.execute_detailed_async("GET", url)
            assert isinstance(caught.value, NavigationGuardrailError)
            assert client._async_client.request.call_count == 0

    asyncio.run(run())


def _strict_navigation_response(kind):
    if kind == "redirect":
        return _transport_response(
            302,
            headers={"Location": "https://dest.test:8443/next"},
            url="https://source.test/start",
        )
    return _transport_response(
        400,
        {
            "next_action": {
                "method": "GET",
                "url": "https://dest.test:8443/next",
                "instruction_for_agent": "Continue to the approved destination",
            }
        },
        url="https://source.test/start",
    )


@pytest.mark.parametrize("kind", ["redirect", "hateoas"])
@pytest.mark.parametrize("exact_policy", [False, True], ids=["host-only", "exact-port"])
def test_navigation_destination_uses_strict_local_netloc_before_sync_transport(
    kind, exact_policy
):
    destination_policy = "dest.test:8443" if exact_policy else "dest.test"
    client = Payment402Client(
        policy=PaymentPolicy(
            allowed_hosts=["source.test", destination_policy]
        ),
        auto_navigate=True,
    )
    context = ExecutionContext(
        hints={"allowed_hosts": ["dest.test:8443"]}
    )
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _strict_navigation_response(kind),
            _transport_response(
                200, {"status": "ok"}, url="https://dest.test:8443/next"
            ),
        ],
    ) as transport:
        if exact_policy:
            result = client.execute_detailed(
                "GET", "https://source.test/start", context=context
            )
            assert result.response == {"status": "ok"}
            assert transport.call_count == 2
        else:
            with pytest.raises(NavigationGuardrailError) as caught:
                client.execute_detailed(
                    "GET", "https://source.test/start", context=context
                )
            assert isinstance(caught.value, NavigationGuardrailError)
            assert transport.call_count == 1


@pytest.mark.parametrize("kind", ["redirect", "hateoas"])
@pytest.mark.parametrize("exact_policy", [False, True], ids=["host-only", "exact-port"])
def test_navigation_destination_uses_strict_local_netloc_before_async_transport(
    kind, exact_policy
):
    async def run():
        destination_policy = "dest.test:8443" if exact_policy else "dest.test"
        client = Payment402Client(
            policy=PaymentPolicy(
                allowed_hosts=["source.test", destination_policy]
            ),
            auto_navigate=True,
        )
        context = ExecutionContext(
            hints={"allowed_hosts": ["dest.test:8443"]}
        )
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _strict_navigation_response(kind),
                _transport_response(
                    200,
                    {"status": "ok"},
                    url="https://dest.test:8443/next",
                ),
            ]
        )
        if exact_policy:
            result = await client.execute_detailed_async(
                "GET", "https://source.test/start", context=context
            )
            assert result.response == {"status": "ok"}
            assert client._async_client.request.call_count == 2
        else:
            with pytest.raises(NavigationGuardrailError) as caught:
                await client.execute_detailed_async(
                    "GET", "https://source.test/start", context=context
                )
            assert isinstance(caught.value, NavigationGuardrailError)
            assert client._async_client.request.call_count == 1

    asyncio.run(run())


def test_async_hateoas_uses_same_transport_level_secret_sanitizer():
    async def run():
        client = Payment402Client(auto_navigate=True)
        context = ExecutionContext(
            hints={"allowed_hosts": ["dest.test"]}
        )
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _transport_response(
                    400,
                    {
                        "next_action": {
                            "method": "GET",
                            "url": "https://dest.test/next",
                            "instruction_for_agent": "Continue safely",
                            "suggested_headers": {
                                **SENSITIVE_HEADERS,
                                "X-Safe": "keep",
                            },
                            "suggested_payload": {
                                "nested": [{"proof": "drop", "visible": "keep"}]
                            },
                        }
                    },
                ),
                _transport_response(200, {"status": "ok"}),
            ]
        )
        result = await client.execute_detailed_async(
            "GET",
            "https://source.test/start",
            payload=_nested_secret_payload(),
            headers={**SENSITIVE_HEADERS, "X-Original-Safe": "keep"},
            context=context,
        )
        second_call = client._async_client.request.call_args_list[1]
        assert result.response == {"status": "ok"}
        _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
        assert second_call.kwargs["headers"]["X-Safe"] == "keep"
        assert second_call.kwargs["headers"]["X-Original-Safe"] == "keep"
        expected_params = {"nested": [{"visible": "keep"}]}
        assert second_call.kwargs["params"] is None
        expected_wire = client._final_wire_url(
            "GET", "https://dest.test/next", expected_params
        )
        assert second_call.args[1] == expected_wire.replace(
            "https://dest.test", "https://93.184.216.34"
        )

    asyncio.run(run())


def test_cross_origin_redirect_async_drops_all_original_headers_and_payload():
    async def run():
        client = Payment402Client()
        context = ExecutionContext(
            hints={"allowed_hosts": ["dest.test"]}
        )
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _transport_response(
                    302,
                    headers={"Location": "https://dest.test/next"},
                    url="https://source.test/start",
                ),
                _transport_response(
                    200, {"status": "ok"}, url="https://dest.test/next"
                ),
            ]
        )
        result = await client.execute_detailed_async(
            "GET",
            "https://source.test/start",
            payload=_nested_secret_payload(),
            headers={**SENSITIVE_HEADERS, "X-Safe": "keep"},
            context=context,
        )

        second_call = client._async_client.request.call_args_list[1]
        assert result.response == {"status": "ok"}
        _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
        assert second_call.kwargs["headers"]["X-Safe"] == "keep"
        assert second_call.kwargs["params"] is None
        assert second_call.kwargs["headers"]["Host"] == "dest.test"
        assert urlparse(second_call.args[1]).path == "/next"
        assert second_call.kwargs["json"] is None

    asyncio.run(run())


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_cross_origin_hateoas_post_uses_only_sanitized_suggested_json(async_mode):
    first = _transport_response(
        400,
        {
            "next_action": {
                "method": "POST",
                "url": "https://dest.test/next",
                "instruction_for_agent": "Submit the sanitized continuation",
                "suggested_headers": {
                    **SENSITIVE_HEADERS,
                    "X-Suggested-Safe": "keep",
                },
                "suggested_payload": {
                    "safe_suggested": "keep",
                    "nested": [
                        {
                            "clientSecret": "drop",
                            "paymentSignature": "drop",
                            "wallet_private_key": "drop",
                            "serviceApiKey": "drop",
                            "l402-macaroon": "drop",
                            "paymentPreimage": "drop",
                            "raw authorization": "drop",
                            "visible": "keep",
                        }
                    ],
                },
            }
        },
        url="https://source.test/start",
    )
    second = _transport_response(
        200, {"status": "ok"}, url="https://dest.test/next"
    )
    context = ExecutionContext(hints={"allowed_hosts": ["dest.test"]})
    client = Payment402Client(
        auto_navigate=True,
        allow_unsafe_navigate=True,
    )

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[first, second]
            )
            result = await client.execute_detailed_async(
                "GET",
                "https://source.test/start",
                payload=_nested_secret_payload(),
                headers={**SENSITIVE_HEADERS, "X-Original-Safe": "keep"},
                context=context,
            )
            return result, client._async_client.request

        result, transport = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[first, second],
        ) as transport:
            result = client.execute_detailed(
                "GET",
                "https://source.test/start",
                payload=_nested_secret_payload(),
                headers={**SENSITIVE_HEADERS, "X-Original-Safe": "keep"},
                context=context,
            )

    second_call = transport.call_args_list[1]
    assert result.response == {"status": "ok"}
    _assert_sensitive_header_families_absent(second_call.kwargs["headers"])
    assert second_call.kwargs["headers"]["X-Original-Safe"] == "keep"
    assert second_call.kwargs["headers"]["X-Suggested-Safe"] == "keep"
    assert second_call.kwargs["json"] == {
        "safe_suggested": "keep",
        "nested": [{"visible": "keep"}],
    }
    assert second_call.kwargs["params"] is None


def test_paid_retry_second_402_stops_before_second_wallet_call():
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_l402_402(), _l402_402()],
    ):
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            client.execute_detailed("GET", "https://buyer.test/start")

    wallet.pay_invoice.assert_called_once()


def test_hateoas_new_path_keeps_top_level_fingerprint_and_wallet_call_count_one():
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet, auto_navigate=True)
    after_payment = _transport_response(
        400,
        {
            "next_action": {
                "method": "GET",
                "url": "/next",
                "instruction_for_agent": "Continue after paid retry",
            }
        },
        url="https://buyer.test/start",
    )

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _l402_402(),
            after_payment,
            _l402_402(url="https://buyer.test/next"),
        ],
    ) as transport:
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            client.execute_detailed(
                "GET",
                "https://buyer.test/start",
                headers={"Idempotency-Key": "purchase-1"},
            )

    wallet.pay_invoice.assert_called_once()
    assert transport.call_count == 3
    assert transport.call_args_list[2].args[1] == "https://93.184.216.34/next"
    assert transport.call_args_list[2].kwargs["headers"]["Host"] == "buyer.test"
    assert transport.call_args_list[2].kwargs["headers"]["Idempotency-Key"] == (
        "purchase-1"
    )


def test_async_hateoas_new_path_keeps_explicit_operation_fingerprint():
    async def run():
        wallet = MagicMock()
        wallet.pay_invoice.return_value = TEST_PREIMAGE
        client = Payment402Client(ln_adapter=wallet, auto_navigate=True)
        after_payment = _transport_response(
            400,
            {
                "next_action": {
                    "method": "GET",
                    "url": "/next",
                    "instruction_for_agent": "Continue after paid retry",
                }
            },
            url="https://buyer.test/start",
        )
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _l402_402(),
                after_payment,
                _l402_402(url="https://buyer.test/next"),
            ]
        )

        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            await client.execute_detailed_async(
                "GET",
                "https://buyer.test/start",
                headers={"Idempotency-Key": "purchase-1"},
            )

        wallet.pay_invoice.assert_called_once()
        assert client._async_client.request.call_count == 3
        third_call = client._async_client.request.call_args_list[2]
        assert third_call.args[1] == "https://93.184.216.34/next"
        assert third_call.kwargs["headers"]["Host"] == "buyer.test"
        assert third_call.kwargs["extensions"]["sni_hostname"] == "buyer.test"
        assert third_call.kwargs["headers"]["Idempotency-Key"] == "purchase-1"

    asyncio.run(run())


class _CachedCredentialExecutor:
    def __init__(self):
        self.calls = 0

    def execute_l402(self, url, method, parsed, headers, payload):
        self.calls += 1
        return L402ExecutionReport(
            delegate_source="lightninglabs",
            authorization_value=(
                f"L402 {parsed.parameters['macaroon']}:{TEST_PREIMAGE}"
            ),
            preimage=TEST_PREIMAGE,
            payment_hash=hashlib.sha256(
                bytes.fromhex(TEST_PREIMAGE)
            ).hexdigest(),
            payment_performed=False,
            cached_token_used=True,
            endpoint=url,
        )


def _cached_client(executor, evidence_repo=None):
    return Payment402Client(
        ln_adapter=MagicMock(),
        l402_executor=executor,
        prefer_lightninglabs_l402=True,
        l402_delegate_allowed_hosts=["buyer.test"],
        evidence_repo=evidence_repo,
    )


def test_credential_reused_is_terminal_before_irreversible_reentry():
    executor = _CachedCredentialExecutor()
    client = _cached_client(executor)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_l402_402(), _l402_402()],
    ):
        with pytest.raises(PaymentExecutionError, match="credential_delivery_failed"):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert executor.calls == 1
    with patch(
        "ln_church_agent.client.requests.request", return_value=_l402_402()
    ):
        with pytest.raises(PaymentExecutionError, match="state is credential_reused"):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )
    assert executor.calls == 1


def test_terminal_state_has_priority_over_max_payment_retry_limit():
    executor = _CachedCredentialExecutor()
    client = _cached_client(executor)
    client.max_payment_retries = 0
    context = ExecutionContext()
    idempotency_key = "terminal-priority-operation"
    context._idempotency_key = idempotency_key
    fingerprint = client._compute_fingerprint(
        "GET", "https://buyer.test/start", {}, idempotency_key
    )
    context.set_payment_state(fingerprint, "credential_reused")

    with patch(
        "ln_church_agent.client.requests.request", return_value=_l402_402()
    ):
        with pytest.raises(PaymentExecutionError, match="credential_reused") as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert "Max 402 retries" not in str(caught.value)
    assert executor.calls == 0


def test_ambiguous_wallet_timeout_reserves_exact_canonical_amount_once():
    wallet = MagicMock()
    wallet.pay_invoice.side_effect = TimeoutError("wallet result lost")
    evidence = _CaptureEvidence()
    policy = PaymentPolicy(max_spend_per_tx_usd=5.0, max_spend_per_session_usd=10.0)
    client = Payment402Client(
        ln_adapter=wallet,
        policy=policy,
        evidence_repo=evidence,
    )
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_l402_402(msats=1_000_000),
    ):
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert "ambiguous_payment_result" in str(caught.value)
    assert wallet.pay_invoice.call_count == 1
    assert policy._session_spent_usd == 0
    assert policy._session_reserved_usd == pytest.approx(0.65)
    assert list(context._ambiguous_reservations.values()) == [Decimal("0.650000")]
    assert [record.session_spend_delta_usd for record in evidence.records] == [0.0]
    assert [record.session_budget_event for record in evidence.records] == [
        "reserved"
    ]
    assert evidence.records[0].session_budget_amount_usd == pytest.approx(0.65)

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_l402_402(msats=1_000_000),
    ):
        with pytest.raises(PaymentExecutionError, match="state is ambiguous"):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert wallet.pay_invoice.call_count == 1
    assert policy._session_spent_usd == 0
    assert policy._session_reserved_usd == pytest.approx(0.65)
    assert len(context._ambiguous_reservations) == 1


def test_fail_closed_validation_before_wallet_has_no_ambiguous_reserve():
    wallet = MagicMock()
    evidence = _CaptureEvidence()
    policy = PaymentPolicy()
    client = Payment402Client(
        ln_adapter=wallet,
        policy=policy,
        evidence_repo=evidence,
    )
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_l402_402(invoice="lnbc1"),
    ):
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    wallet.pay_invoice.assert_not_called()
    assert policy._session_spent_usd == 0
    assert context._ambiguous_reservations == {}
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert all(record.session_spend_delta_usd in (None, 0) for record in evidence.records)


def _exception_chain(error):
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _assert_error_chain_excludes(error, *secrets):
    chain = list(_exception_chain(error))
    assert chain == [error]
    for item in chain:
        rendered = str(item) + repr(item)
        for secret in secrets:
            assert secret not in rendered


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_pre_irreversible_primary_error_survives_evidence_export_failure(async_mode):
    signer_secret = "DUMMY_PREVALIDATION_SIGNER_SECRET"

    class RaisingSigner:
        address = EVM_SIGNER

        def __init__(self):
            self.calls = 0

        def generate_eip3009_payload_atomic(self, **kwargs):
            self.calls += 1
            raise RuntimeError(signer_secret)

    signer = RaisingSigner()
    repo = _FailingEvidence()
    context = ExecutionContext()
    client = Payment402Client(evm_signer=signer, evidence_repo=repo)

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(return_value=_exact_402())
            with pytest.raises(RuntimeError) as caught:
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )
            return caught.value, client._async_client.request.call_count

        error, transport_calls = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request", return_value=_exact_402()
        ) as transport:
            with pytest.raises(RuntimeError) as caught:
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
        error, transport_calls = caught.value, transport.call_count

    assert signer.calls == 1
    assert transport_calls == 1
    assert repo.export_calls == 1
    _assert_error_chain_excludes(
        error, signer_secret, _FailingEvidence.SECRET
    )
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_result_unknown_primary_error_survives_evidence_export_failure(async_mode):
    wallet_secret = "DUMMY_RESULT_UNKNOWN_WALLET_SECRET"
    wallet = MagicMock()
    wallet.pay_invoice.side_effect = RuntimeError(wallet_secret)
    repo = _FailingEvidence()
    policy = PaymentPolicy(
        max_spend_per_tx_usd=5.0,
        max_spend_per_session_usd=10.0,
    )
    context = ExecutionContext()
    client = Payment402Client(
        ln_adapter=wallet, evidence_repo=repo, policy=policy
    )

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                return_value=_l402_402(msats=1_000_000)
            )
            with pytest.raises(PaymentExecutionError) as caught:
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )
            return caught.value, client._async_client.request.call_count

        error, transport_calls = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            return_value=_l402_402(msats=1_000_000),
        ) as transport:
            with pytest.raises(PaymentExecutionError) as caught:
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
        error, transport_calls = caught.value, transport.call_count

    assert "ambiguous_payment_result" in str(error)
    assert wallet.pay_invoice.call_count == 1
    assert transport_calls == 1
    assert repo.export_calls == 1
    _assert_error_chain_excludes(
        error, wallet_secret, _FailingEvidence.SECRET
    )
    assert set(context._payment_states.values()) == {"ambiguous"}
    assert list(context._ambiguous_reservations.values()) == [
        Decimal("0.650000")
    ]
    assert policy._session_spent_usd == 0
    assert policy._session_reserved_usd == pytest.approx(0.65)


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_paid_success_is_not_replaced_by_evidence_export_failure(async_mode):
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    repo = _FailingEvidence()
    context = ExecutionContext()
    client = Payment402Client(ln_adapter=wallet, evidence_repo=repo)

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[
                    _l402_402(msats=1000),
                    _transport_response(200, {"status": "paid"}),
                ]
            )
            result = await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )
            return result, client._async_client.request.call_count

        result, transport_calls = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[
                _l402_402(msats=1000),
                _transport_response(200, {"status": "paid"}),
            ],
        ) as transport:
            result = client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )
        transport_calls = transport.call_count

    assert result.response == {"status": "paid"}
    assert wallet.pay_invoice.call_count == 1
    assert transport_calls == 2
    assert repo.export_calls == 1
    assert set(context._payment_states.values()) == {"completed"}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == pytest.approx(0.00065)


def test_secret_is_absent_from_public_error_evidence_cause_and_context_chain():
    secret = "DUMMY_WALLET_SECRET_7f45aa19"
    wallet = MagicMock()
    wallet.pay_invoice.side_effect = RuntimeError(secret)
    evidence = _CaptureEvidence()
    client = Payment402Client(ln_adapter=wallet, evidence_repo=evidence)

    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_l402_402(msats=1000),
    ):
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed("GET", "https://buyer.test/start")

    chain = list(_exception_chain(caught.value))
    assert len(chain) == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    for error in chain:
        assert secret not in str(error)
        assert secret not in repr(error)
    assert secret not in "".join(record.model_dump_json() for record in evidence.records)


def test_cached_credential_has_zero_session_spend_evidence_delta_and_reserve():
    executor = _CachedCredentialExecutor()
    evidence = _CaptureEvidence()
    policy = PaymentPolicy()
    client = _cached_client(executor, evidence_repo=evidence)
    client.policy = policy
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _l402_402(msats=1000),
            _transport_response(200, {"status": "cached"}),
        ],
    ):
        result = client.execute_detailed(
            "GET", "https://buyer.test/start", context=context
        )

    assert result.response == {"status": "cached"}
    assert executor.calls == 1
    assert policy._session_spent_usd == 0
    assert context._ambiguous_reservations == {}
    payment_records = [record for record in evidence.records if record.scheme == "L402"]
    assert len(payment_records) == 1
    assert payment_records[0].payment_performed is False
    assert payment_records[0].cached_token_used is True
    assert payment_records[0].session_spend_delta_usd == 0


def test_fresh_contexts_allow_two_real_purchases():
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _l402_402(),
            _transport_response(200, {"purchase": 1}),
            _l402_402(),
            _transport_response(200, {"purchase": 2}),
        ],
    ):
        first = client.execute_detailed(
            "GET", "https://buyer.test/start", context=ExecutionContext()
        )
        second = client.execute_detailed(
            "GET", "https://buyer.test/start", context=ExecutionContext()
        )

    assert first.response == {"purchase": 1}
    assert second.response == {"purchase": 2}
    assert wallet.pay_invoice.call_count == 2


def test_sync_hateoas_ambiguous_flow_has_one_irreversible_call():
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet, auto_navigate=True)
    next_action = _transport_response(
        400,
        {
            "next_action": {
                "method": "GET",
                "url": "/sync-next",
                "instruction_for_agent": "Continue sync flow",
            }
        },
    )

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_l402_402(), next_action, _l402_402()],
    ):
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            client.execute_detailed("GET", "https://buyer.test/start")

    wallet.pay_invoice.assert_called_once()


def test_async_hateoas_ambiguous_flow_has_one_irreversible_call():
    async def run():
        wallet = MagicMock()
        wallet.pay_invoice.return_value = TEST_PREIMAGE
        client = Payment402Client(ln_adapter=wallet, auto_navigate=True)
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _l402_402(),
                _transport_response(
                    400,
                    {
                        "next_action": {
                            "method": "GET",
                            "url": "/async-next",
                            "instruction_for_agent": "Continue async flow",
                        }
                    },
                ),
                _l402_402(),
            ]
        )
        with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start"
            )
        wallet.pay_invoice.assert_called_once()
        assert client._async_client.request.call_count == 3

    asyncio.run(run())


def test_sync_pre_payment_transport_error_preserves_requests_type_and_state():
    secret = "DUMMY_PREPAYMENT_TRANSPORT_SECRET"
    client = Payment402Client()
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=requests.ConnectTimeout(secret),
    ):
        with pytest.raises(requests.ConnectTimeout) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert not isinstance(caught.value, PaymentExecutionError)
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert context._payment_states == {}
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == 0


def test_async_pre_payment_transport_error_preserves_httpx_type_and_state():
    async def run():
        secret = "DUMMY_ASYNC_PREPAYMENT_TRANSPORT_SECRET"
        client = Payment402Client()
        context = ExecutionContext()
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=httpx.ReadTimeout(
                secret, request=httpx.Request("GET", "https://buyer.test/start")
            )
        )

        with pytest.raises(httpx.ReadTimeout) as caught:
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )

        assert not isinstance(caught.value, PaymentExecutionError)
        assert secret not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert context._payment_states == {}
        assert context._ambiguous_reservations == {}
        assert client.policy._session_spent_usd == 0

    asyncio.run(run())


def test_pre_irreversible_invoice_error_preserves_type_without_reserve():
    secret = "DUMMY_PRE_VALIDATION_SECRET_4a81"
    evidence = _CaptureEvidence()
    client = Payment402Client(
        ln_adapter=MagicMock(), evidence_repo=evidence
    )
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request", return_value=_l402_402()
    ), patch.object(
        client,
        "_process_payment",
        side_effect=InvoiceParseError(secret),
    ):
        with pytest.raises(InvoiceParseError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert list(_exception_chain(caught.value)) == [caught.value]
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert secret not in "".join(
        record.model_dump_json() for record in evidence.records
    )
    assert context._ambiguous_reservations == {}
    assert set(context._payment_states.values()) == {"validation_failed"}
    assert client.policy._session_spent_usd == 0


def test_pre_irreversible_nonstandard_exception_constructor_preserves_type():
    class TwoArgumentInvoiceError(InvoiceParseError):
        def __init__(self, message, code):
            super().__init__(message, code)

    client = Payment402Client(ln_adapter=MagicMock())
    original = TwoArgumentInvoiceError("DUMMY_NONSTANDARD_SECRET", 17)
    with patch(
        "ln_church_agent.client.requests.request", return_value=_l402_402()
    ), patch.object(client, "_process_payment", side_effect=original):
        with pytest.raises(TwoArgumentInvoiceError) as caught:
            client.execute_detailed("GET", "https://buyer.test/start")

    assert "DUMMY_NONSTANDARD_SECRET" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_paid_retry_transport_loss_is_secret_free_without_double_reserve():
    secret = "DUMMY_PAID_RETRY_TRANSPORT_SECRET"
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_l402_402(), requests.RequestException(secret)],
    ):
        with pytest.raises(PaymentExecutionError) as caught:
            client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )

    assert "ambiguous_payment_result" in str(caught.value)
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    wallet.pay_invoice.assert_called_once()
    assert context._ambiguous_reservations == {}
    assert client.policy._session_spent_usd == pytest.approx(0.00065)


def test_async_paid_retry_transport_loss_is_secret_free_without_double_reserve():
    async def run():
        secret = "DUMMY_ASYNC_PAID_RETRY_SECRET_617c"
        wallet = MagicMock()
        wallet.pay_invoice.return_value = TEST_PREIMAGE
        evidence = _CaptureEvidence()
        client = Payment402Client(
            ln_adapter=wallet, evidence_repo=evidence
        )
        context = ExecutionContext()
        request = httpx.Request("GET", "https://buyer.test/start")
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _l402_402(),
                httpx.ReadTimeout(secret, request=request),
            ]
        )

        with pytest.raises(PaymentExecutionError) as caught:
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )

        chain = list(_exception_chain(caught.value))
        assert chain == [caught.value]
        assert secret not in str(caught.value)
        assert secret not in repr(caught.value)
        assert secret not in "".join(
            record.model_dump_json() for record in evidence.records
        )
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        wallet.pay_invoice.assert_called_once()
        assert client.policy._session_spent_usd == pytest.approx(0.00065)
        assert context._ambiguous_reservations == {}

    asyncio.run(run())


def test_async_irreversible_wallet_error_reserves_once_and_blocks_reentry():
    async def run():
        secret = "DUMMY_ASYNC_WALLET_SECRET_82d1"
        wallet = MagicMock()
        wallet.pay_invoice.side_effect = RuntimeError(secret)
        evidence = _CaptureEvidence()
        policy = PaymentPolicy(
            max_spend_per_tx_usd=5.0,
            max_spend_per_session_usd=10.0,
        )
        client = Payment402Client(
            ln_adapter=wallet,
            evidence_repo=evidence,
            policy=policy,
        )
        context = ExecutionContext()
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            return_value=_l402_402(msats=1_000_000)
        )

        with pytest.raises(PaymentExecutionError) as caught:
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )

        chain = list(_exception_chain(caught.value))
        assert chain == [caught.value]
        assert secret not in str(caught.value)
        assert secret not in repr(caught.value)
        assert secret not in "".join(
            record.model_dump_json() for record in evidence.records
        )
        assert policy._session_spent_usd == 0
        assert policy._session_reserved_usd == pytest.approx(0.65)
        assert list(context._ambiguous_reservations.values()) == [
            Decimal("0.650000")
        ]
        wallet.pay_invoice.assert_called_once()

        client._async_client.request = AsyncMock(
            return_value=_l402_402(msats=1_000_000)
        )
        with pytest.raises(PaymentExecutionError, match="state is ambiguous"):
            await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )

        wallet.pay_invoice.assert_called_once()
        assert policy._session_spent_usd == 0
        assert policy._session_reserved_usd == pytest.approx(0.65)
        assert len(context._ambiguous_reservations) == 1

    asyncio.run(run())


def test_same_context_same_explicit_idempotency_key_rejects_second_purchase():
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _l402_402(),
            _transport_response(200, {"purchase": 1}),
            _l402_402(),
        ],
    ) as transport:
        first = client.execute_detailed(
            "GET",
            "https://buyer.test/start",
            headers={"Idempotency-Key": "purchase-1"},
            context=context,
        )
        with pytest.raises(PaymentExecutionError, match="state is completed"):
            client.execute_detailed(
                "GET",
                "https://buyer.test/start",
                headers={"Idempotency-Key": "purchase-1"},
                context=context,
            )

    assert first.response == {"purchase": 1}
    wallet.pay_invoice.assert_called_once()
    assert transport.call_count == 3


def test_same_context_different_idempotency_rejects_reused_payment_identity():
    wallet = MagicMock()
    wallet.pay_invoice.return_value = TEST_PREIMAGE
    client = Payment402Client(ln_adapter=wallet)
    context = ExecutionContext()

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _l402_402(),
            _transport_response(200, {"purchase": 1}),
            _l402_402(),
            _transport_response(200, {"purchase": 2}),
        ],
    ) as transport:
        first = client.execute_detailed(
            "GET",
            "https://buyer.test/start",
            headers={"Idempotency-Key": "purchase-1"},
            context=context,
        )
        with pytest.raises(
            PaymentExecutionError,
            match="Payment identity was reused",
        ):
            client.execute_detailed(
                "GET",
                "https://buyer.test/start",
                headers={"Idempotency-Key": "purchase-2"},
                context=context,
            )

    assert first.response == {"purchase": 1}
    wallet.pay_invoice.assert_called_once()
    assert transport.call_count == 3


@pytest.mark.parametrize(
    "max_tx,max_session",
    [(0.0, 1.0), (1.0, 0.0)],
    ids=["transaction-zero", "session-zero"],
)
def test_one_msat_with_independent_zero_budget_stops_before_wallet(
    max_tx, max_session
):
    wallet = MagicMock()
    policy = PaymentPolicy(
        max_spend_per_tx_usd=max_tx,
        max_spend_per_session_usd=max_session,
    )
    client = Payment402Client(ln_adapter=wallet, policy=policy)

    with patch(
        "ln_church_agent.client.requests.request", return_value=_l402_402(msats=1)
    ) as transport:
        with pytest.raises(PaymentExecutionError):
            client.execute_detailed("GET", "https://buyer.test/start")

    wallet.pay_invoice.assert_not_called()
    assert policy._session_spent_usd == 0
    assert transport.call_count == 1


def test_audit_evm_signature_is_expiry_and_requirement_bound():
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"status": "paid"})],
    ) as transport:
        result = client.execute_detailed(
            "GET",
            "https://buyer.test/start",
            headers={"Idempotency-Key": "audit-expiry-binding"},
        )

    requirement = client._last_parsed_challenge._canonical_requirement
    envelope = json.loads(
        base64.urlsafe_b64decode(
            transport.call_args_list[1].kwargs["headers"]["PAYMENT-SIGNATURE"]
            + "=="
        )
    )
    authorization = envelope["payload"]["authorization"]
    assert int(authorization["validBefore"]) <= int(requirement["expires_at"])
    assert authorization["nonce"] == derive_eip3009_requirement_nonce(
        requirement["requirement_hash"], requirement["idempotency_key"]
    )
    binding = envelope["extensions"]["lnChurchCanonicalBinding"]
    assert binding["requirementHash"] == requirement["requirement_hash"]
    assert binding["expiresAt"] == requirement["expires_at"]
    assert result.settlement_receipt.payment_performed is True


@pytest.mark.parametrize(
    "tamper",
    ["expiry", "nonce"],
    ids=["canonical-expiry-overrun", "alternate-requirement-nonce"],
)
def test_audit_rejects_validly_signed_evm_output_outside_canonical_bounds(tamper):
    """A pluggable signer cannot widen or replace the approved authorization."""
    backing = LocalKeyAdapter(EVM_PRIVATE_KEY)

    class RebindingSigner:
        address = backing.address

        def generate_eip3009_payload_atomic(self, **kwargs):
            altered = dict(kwargs)
            if tamper == "expiry":
                altered["valid_before"] = int(kwargs["valid_before"]) + 1
            else:
                altered["idempotency_key"] = (
                    str(kwargs["idempotency_key"]) + "-different-operation"
                )
            return backing.generate_eip3009_payload_atomic(**altered)

    client = Payment402Client(evm_signer=RebindingSigner())
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[_exact_402(), _transport_response(200, {"unexpected": True})],
    ) as transport:
        with pytest.raises(
            PaymentExecutionError,
            match=(
                "outlives the canonical requirement"
                if tamper == "expiry"
                else "nonce is not bound to the canonical requirement"
            ),
        ):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert transport.call_count == 1
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == 0


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_exact_transport_unknown_is_reserved_and_recoverable(async_mode):
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    context = ExecutionContext()

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[
                    _exact_402(),
                    httpx.ReadTimeout(
                        "lost",
                        request=httpx.Request("GET", "https://buyer.test/start"),
                    ),
                ]
            )
            with pytest.raises(PaymentExecutionError, match="settlement_unknown"):
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )

        asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[_exact_402(), requests.ReadTimeout("lost")],
        ):
            with pytest.raises(PaymentExecutionError, match="settlement_unknown"):
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )

    fingerprint, state = next(
        iter(client.get_payment_operation_states(context).items())
    )
    assert state["state"] == "settlement_unknown"
    assert client.last_receipt.payment_performed is False
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == pytest.approx(1.0)
    assert context._ambiguous_reservations[fingerprint] == Decimal("1.0")
    assert client.resolve_ambiguous_payment(
        context, fingerprint, "confirmed_not_paid"
    ) == "confirmed_not_paid"
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == 0
    assert context._ambiguous_reservations == {}

    if async_mode:
        async def retry():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[
                    _exact_402(),
                    _transport_response(200, {"status": "paid-after-check"}),
                ]
            )
            return await client.execute_detailed_async(
                "GET", "https://buyer.test/start", context=context
            )

        retry_result = asyncio.run(retry())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[
                _exact_402(),
                _transport_response(200, {"status": "paid-after-check"}),
            ],
        ):
            retry_result = client.execute_detailed(
                "GET", "https://buyer.test/start", context=context
            )
    assert retry_result.response == {"status": "paid-after-check"}
    assert set(context._payment_states.values()) == {"completed"}
    assert client.policy._session_spent_usd == pytest.approx(1.0)


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_unknown_budget_journal_survives_restart_and_release(async_mode):
    evidence = _PersistentEvidence()
    session_id = "durable-settlement-unknown"
    operation_headers = {"Idempotency-Key": "durable-operation"}
    client = Payment402Client(
        private_key=EVM_PRIVATE_KEY,
        policy=PaymentPolicy(max_spend_per_session_usd=1.5),
        evidence_repo=evidence,
    )
    context = ExecutionContext(session_id=session_id)

    if async_mode:
        async def lose_response():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[
                    _exact_402(),
                    httpx.ReadTimeout(
                        "lost",
                        request=httpx.Request(
                            "GET", "https://buyer.test/start"
                        ),
                    ),
                ]
            )
            with pytest.raises(
                PaymentExecutionError, match="settlement_unknown"
            ):
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start",
                    headers=operation_headers, context=context
                )

        asyncio.run(lose_response())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[_exact_402(), requests.ReadTimeout("lost")],
        ):
            with pytest.raises(
                PaymentExecutionError, match="settlement_unknown"
            ):
                client.execute_detailed(
                    "GET", "https://buyer.test/start",
                    headers=operation_headers, context=context
                )

    reserved = [
        record for record in evidence.records
        if record.session_budget_event == "reserved"
    ]
    assert len(reserved) == 1
    assert reserved[0].session_spend_delta_usd == 0
    assert reserved[0].session_budget_amount_usd == pytest.approx(1.0)
    operation_id = reserved[0].session_budget_operation_id

    restarted = Payment402Client(
        private_key=EVM_PRIVATE_KEY,
        policy=PaymentPolicy(max_spend_per_session_usd=1.5),
        evidence_repo=evidence,
    )
    restarted_context = ExecutionContext(session_id=session_id)
    if async_mode:
        asyncio.run(
            restarted._restore_session_spend_from_evidence_async(
                restarted_context
            )
        )
    else:
        restarted._restore_session_spend_from_evidence(restarted_context)

    assert restarted.policy._session_spent_usd == 0
    assert restarted.policy._session_reserved_usd == pytest.approx(1.0)
    assert restarted_context.get_payment_state(operation_id) == "settlement_unknown"
    with pytest.raises(PaymentExecutionError, match="including reservations"):
        restarted._reserve_session_budget(
            restarted_context, "different-operation", "1.0"
        )

    if async_mode:
        assert asyncio.run(
            restarted.resolve_ambiguous_payment_async(
                restarted_context, operation_id, "confirmed_not_paid"
            )
        ) == "confirmed_not_paid"
    else:
        assert restarted.resolve_ambiguous_payment(
            restarted_context, operation_id, "confirmed_not_paid"
        ) == "confirmed_not_paid"

    assert [
        record.session_budget_event for record in evidence.records
        if record.session_budget_event
    ] == ["reserved", "released"]

    # The same logical operation may be retried after confirmed_not_paid.  A
    # second lost response must create a new reservation even though an older
    # release exists in the journal.
    if async_mode:
        async def lose_retry_response():
            restarted._async_client = MagicMock()
            restarted._async_client.request = AsyncMock(
                side_effect=[
                    _exact_402(),
                    httpx.ReadTimeout(
                        "lost-again",
                        request=httpx.Request(
                            "GET", "https://buyer.test/start"
                        ),
                    ),
                ]
            )
            with pytest.raises(
                PaymentExecutionError, match="settlement_unknown"
            ):
                await restarted.execute_detailed_async(
                    "GET", "https://buyer.test/start",
                    headers=operation_headers, context=restarted_context,
                )

        asyncio.run(lose_retry_response())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[_exact_402(), requests.ReadTimeout("lost-again")],
        ):
            with pytest.raises(
                PaymentExecutionError, match="settlement_unknown"
            ):
                restarted.execute_detailed(
                    "GET", "https://buyer.test/start",
                    headers=operation_headers, context=restarted_context,
                )

    assert [
        record.session_budget_event for record in evidence.records
        if record.session_budget_event
    ] == ["reserved", "released", "reserved"]

    second_restart = Payment402Client(
        policy=PaymentPolicy(max_spend_per_session_usd=1.5),
        evidence_repo=evidence,
    )
    second_context = ExecutionContext(session_id=session_id)
    if async_mode:
        asyncio.run(
            second_restart._restore_session_spend_from_evidence_async(
                second_context
            )
        )
        assert asyncio.run(
            second_restart.resolve_ambiguous_payment_async(
                second_context, operation_id, "confirmed_not_paid"
            )
        ) == "confirmed_not_paid"
    else:
        second_restart._restore_session_spend_from_evidence(second_context)
        assert second_restart.resolve_ambiguous_payment(
            second_context, operation_id, "confirmed_not_paid"
        ) == "confirmed_not_paid"
    assert second_restart.policy._session_spent_usd == 0
    assert second_restart.policy._session_reserved_usd == 0

    final_client = Payment402Client(
        policy=PaymentPolicy(max_spend_per_session_usd=1.5),
        evidence_repo=evidence,
    )
    final_context = ExecutionContext(session_id=session_id)
    if async_mode:
        asyncio.run(
            final_client._restore_session_spend_from_evidence_async(
                final_context
            )
        )
    else:
        final_client._restore_session_spend_from_evidence(final_context)
    assert final_client.policy._session_spent_usd == 0
    assert final_client.policy._session_reserved_usd == 0
    assert final_context.list_payment_states() == {}


def test_audit_get_query_is_materialized_once_before_x402_approval():
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    query = {"q": "a/b", "page": "1"}
    wire_url = client._final_wire_url(
        "GET", "https://buyer.test/start?existing=%2f", query
    )
    challenge = _exact_payload()
    challenge["resource"]["url"] = wire_url
    challenge["resource"]["method"] = "GET"

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _exact_402(challenge, url=wire_url),
            _transport_response(200, {"status": "paid"}, url=wire_url),
        ],
    ) as transport:
        result = client.execute_detailed(
            "GET", "https://buyer.test/start?existing=%2f", payload=query
        )

    assert wire_url.endswith("existing=%2F&q=a%2Fb&page=1")
    assert transport.call_args_list[0].args[1] == wire_url
    assert transport.call_args_list[1].args[1] == wire_url
    assert transport.call_args_list[0].kwargs["params"] is None
    assert transport.call_args_list[1].kwargs["params"] is None
    assert client._last_parsed_challenge._canonical_requirement[
        "resource_url"
    ] == wire_url
    assert result.final_url == wire_url


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("transport_fails", [False, True], ids=["success", "failure"])
def test_audit_evidence_redacts_secret_wire_query_at_export_boundary(
    async_mode, transport_fails
):
    evidence = _CaptureEvidence()
    client = Payment402Client(
        private_key=EVM_PRIVATE_KEY, evidence_repo=evidence
    )
    query = {
        "q": "public-search",
        "api_key": "plain-api-secret",
        "access_token": "plain-access-secret",
        "password": "plain-password-secret",
        "sig": "plain-short-signature",
        "jwt": "plain-jwt-secret",
        "auth": "plain-auth-secret",
        "code": "plain-oauth-code",
        "state": "plain-oauth-state",
        "key": "plain-short-key",
        "X-Amz-Signature": "plain-amz-signature",
        "X-Goog-Signature": "plain-goog-signature",
        "X-Goog-Credential": "plain-goog-credential",
        "X-Amz-Security-Token": "plain-amz-security-token",
    }
    wire_url = client._final_wire_url(
        "GET", "https://buyer.test/start", query
    )
    redacted_wire_url = client._final_wire_url(
        "GET", "https://buyer.test/start",
        {key: "REDACTED" for key in query},
    )
    context = ExecutionContext(
        hints={
            "target_url": wire_url,
            "api_key": "plain-hint-api-key",
            "nested": {"reset_code": "plain-reset-code"},
        }
    )
    context._idempotency_key = "plain-private-idempotency-key"
    context._logical_operation_id = "plain-private-logical-operation"
    context._origin_idempotency_keys = {
        "https://buyer.test": "plain-private-origin-key"
    }
    context._navigation_states = {
        "operation": {"visited": {wire_url}, "hops": 0}
    }
    challenge = _exact_payload()
    challenge["resource"]["url"] = wire_url
    challenge["resource"]["method"] = "GET"

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            second = (
                httpx.ReadTimeout(
                    "lost",
                    request=httpx.Request("GET", wire_url),
                )
                if transport_fails else
                _transport_response(200, {"status": "paid"}, url=wire_url)
            )
            client._async_client.request = AsyncMock(
                side_effect=[_exact_402(challenge, url=wire_url), second]
            )
            if transport_fails:
                with pytest.raises(
                    PaymentExecutionError, match="settlement_unknown"
                ):
                    await client.execute_detailed_async(
                        "GET", "https://buyer.test/start",
                        payload=query,
                        context=context,
                    )
            else:
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", payload=query,
                    context=context,
                )
            return client._async_client.request

        transport = asyncio.run(run())
    else:
        second = (
            requests.ReadTimeout("lost")
            if transport_fails else
            _transport_response(200, {"status": "paid"}, url=wire_url)
        )
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[_exact_402(challenge, url=wire_url), second],
        ) as transport:
            if transport_fails:
                with pytest.raises(
                    PaymentExecutionError, match="settlement_unknown"
                ):
                    client.execute_detailed(
                        "GET", "https://buyer.test/start", payload=query,
                        context=context,
                    )
            else:
                client.execute_detailed(
                    "GET", "https://buyer.test/start", payload=query,
                    context=context,
                )

    assert all(secret in wire_url for secret in query.values())
    assert transport.call_args_list[0].args[1] == wire_url
    assert transport.call_args_list[1].args[1] == wire_url
    assert (
        client._last_parsed_challenge._canonical_requirement["resource_url"]
        == wire_url
    )
    assert evidence.records
    for record in evidence.records:
        assert record.target_url == redacted_wire_url
        exported_query = parse_qs(urlparse(record.target_url).query)
        assert exported_query == {
            "api_key": ["REDACTED"],
            "access_token": ["REDACTED"],
            "password": ["REDACTED"],
            "sig": ["REDACTED"],
            "jwt": ["REDACTED"],
            "auth": ["REDACTED"],
            "code": ["REDACTED"],
            "state": ["REDACTED"],
            "key": ["REDACTED"],
            "X-Amz-Signature": ["REDACTED"],
            "X-Goog-Signature": ["REDACTED"],
            "X-Goog-Credential": ["REDACTED"],
            "X-Amz-Security-Token": ["REDACTED"],
            "q": ["REDACTED"],
        }
    assert evidence.import_urls
    for imported_url in evidence.import_urls:
        assert imported_url == redacted_wire_url
        assert set(
            value
            for values in parse_qs(urlparse(imported_url).query).values()
            for value in values
        ) == {"REDACTED"}
    repo_contexts = (
        evidence.session_import_contexts
        + evidence.import_contexts
        + evidence.export_contexts
    )
    assert repo_contexts
    for repo_context in repo_contexts:
        assert repo_context is not context
        serialized_context = json.dumps(repo_context.model_dump(mode="json"))
        assert "plain-" not in serialized_context
        assert repo_context.hints["api_key"] == "REDACTED"
        assert repo_context.hints["nested"]["reset_code"] == "REDACTED"
        assert repo_context._navigation_states == {}
        assert repo_context._origin_idempotency_keys == {}
        assert repo_context._idempotency_key is None
        assert repo_context._logical_operation_id is None
    assert context.hints["target_url"] == wire_url
    assert context.hints["api_key"] == "plain-hint-api-key"
    assert context._idempotency_key is not None
    serialized = json.dumps(
        [record.model_dump(mode="json") for record in evidence.records]
    )
    assert "plain-api-secret" not in serialized
    assert "plain-access-secret" not in serialized
    assert "plain-password-secret" not in serialized
    assert "public-search" not in serialized
    assert "plain-short-signature" not in serialized
    assert "plain-jwt-secret" not in serialized
    assert "plain-auth-secret" not in serialized
    assert "plain-oauth-code" not in serialized
    assert "plain-oauth-state" not in serialized
    assert "plain-short-key" not in serialized
    assert "plain-amz-signature" not in serialized
    assert "plain-goog-signature" not in serialized
    assert "plain-goog-credential" not in serialized
    assert "plain-amz-security-token" not in serialized


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_local_trust_echo_is_raw_locally_but_sanitized_at_boundaries(
    async_mode,
):
    evidence_repo = _CaptureEvidence()
    query = {
        "api_key": "trust-echo-api-secret",
        "q": "trust-echo-private-query",
    }
    probe = Payment402Client()
    wire_url = probe._final_wire_url(
        "GET", "https://buyer.test/start", query
    )
    challenge = _exact_payload()
    challenge["resource"]["url"] = wire_url
    challenge["resource"]["method"] = "GET"
    raw_reason = (
        f"blocked {wire_url}; api_key=standalone-trust-secret"
    )
    local_decision = TrustDecision(
        is_trusted=False,
        reason=raw_reason,
    )
    local_seen = []

    def local_evaluator(trust_evidence, context):
        local_seen.append(
            (trust_evidence.url, context.hints["target_url"])
        )
        return local_decision

    client = Payment402Client(
        evidence_repo=evidence_repo,
        trust_evaluators=[local_evaluator],
    )
    context = ExecutionContext(hints={"target_url": wire_url})

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                return_value=_exact_402(challenge, url=wire_url)
            )
            with pytest.raises(CounterpartyTrustError) as caught:
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start",
                    payload=query, context=context,
                )
            return caught.value, client._async_client.request

        public_error, transport = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            return_value=_exact_402(challenge, url=wire_url),
        ) as transport:
            with pytest.raises(CounterpartyTrustError) as caught:
                client.execute_detailed(
                    "GET", "https://buyer.test/start",
                    payload=query, context=context,
                )
        public_error = caught.value

    assert transport.call_args.args[1] == wire_url
    assert local_seen == [(wire_url, wire_url)]
    assert local_decision.reason == raw_reason
    public_message = str(public_error)
    assert "trust-echo-api-secret" not in public_message
    assert "trust-echo-private-query" not in public_message
    assert "standalone-trust-secret" not in public_message
    assert "api_key=REDACTED" in public_message
    assert "q=REDACTED" in public_message
    assert "api_key=[REDACTED]" in public_message

    assert len(evidence_repo.records) == 1
    exported = evidence_repo.records[0]
    assert isinstance(exported.trust_decision, TrustDecision)
    assert exported.trust_decision is not local_decision
    exported_query = parse_qs(urlparse(exported.target_url).query)
    assert exported_query == {
        "api_key": ["REDACTED"],
        "q": ["REDACTED"],
    }
    exported_json = json.dumps(exported.model_dump(mode="json"))
    assert "trust-echo-api-secret" not in exported_json
    assert "trust-echo-private-query" not in exported_json
    assert "standalone-trust-secret" not in exported_json
    assert "api_key=REDACTED" in exported.trust_decision.reason
    assert "q=REDACTED" in exported.trust_decision.reason
    assert "api_key=[REDACTED]" in exported.error_message


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_local_outcome_echo_is_raw_for_caller_but_sanitized_for_repo(
    async_mode,
):
    evidence_repo = _CaptureEvidence()
    query = {
        "api_key": "outcome-echo-api-secret",
        "q": "outcome-echo-private-query",
    }
    probe = Payment402Client()
    wire_url = probe._final_wire_url(
        "GET", "https://buyer.test/start", query
    )
    raw_message = (
        f"completed {wire_url}; token=standalone-outcome-secret"
    )
    local_outcome = OutcomeSummary(
        is_success=True,
        observed_state=f"verified at {wire_url}",
        message=raw_message,
        external_evidence={
            "echo": f"proof at {wire_url}",
            "api_key": "nested-outcome-secret",
            "nested": {
                "url": wire_url,
                "public_hint": "safe-advisory-value",
            },
        },
    )
    local_seen = []

    def local_matcher(response, receipt, context):
        local_seen.append(context.hints["target_url"])
        return local_outcome

    context = ExecutionContext()
    response = _transport_response(
        200,
        {"status": "ok", "access_path": "sponsored_grant"},
        url=wire_url,
    )
    client = Payment402Client(evidence_repo=evidence_repo)

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                return_value=response
            )
            result = await client.execute_detailed_async(
                "GET", "https://buyer.test/start", payload=query,
                context=context, outcome_matcher=local_matcher,
            )
            return result, client._async_client.request

        result, transport = asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            return_value=response,
        ) as transport:
            result = client.execute_detailed(
                "GET", "https://buyer.test/start", payload=query,
                context=context, outcome_matcher=local_matcher,
            )

    assert transport.call_args.args[1] == wire_url
    assert local_seen == [wire_url]
    assert result.final_url == wire_url
    assert result.outcome is local_outcome
    assert result.outcome.message == raw_message
    assert result.outcome.external_evidence["echo"] == (
        f"proof at {wire_url}"
    )
    assert (
        result.outcome.external_evidence["api_key"]
        == "nested-outcome-secret"
    )

    assert len(evidence_repo.records) == 1
    exported = evidence_repo.records[0]
    assert isinstance(exported.outcome, OutcomeSummary)
    assert exported.outcome is not local_outcome
    exported_query = parse_qs(urlparse(exported.target_url).query)
    assert exported_query == {
        "api_key": ["REDACTED"],
        "q": ["REDACTED"],
    }
    exported_json = json.dumps(exported.model_dump(mode="json"))
    assert "outcome-echo-api-secret" not in exported_json
    assert "outcome-echo-private-query" not in exported_json
    assert "standalone-outcome-secret" not in exported_json
    assert "nested-outcome-secret" not in exported_json
    assert "api_key=REDACTED" in exported.outcome.message
    assert "q=REDACTED" in exported.outcome.message
    assert "token=[REDACTED]" in exported.outcome.message
    assert exported.outcome.external_evidence["api_key"] == "REDACTED"
    assert (
        exported.outcome.external_evidence["nested"]["public_hint"]
        == "safe-advisory-value"
    )


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_remote_trust_redacts_query_and_hint_copy_only(async_mode):
    query = {
        "api_key": "remote-trust-api-secret",
        "X-Amz-Signature": "remote-trust-presigned-secret",
        "q": "remote-trust-private-query",
    }
    probe = Payment402Client()
    wire_url = probe._final_wire_url(
        "GET", "https://buyer.test/start", query
    )
    challenge = _exact_payload()
    challenge["resource"]["url"] = wire_url
    challenge["resource"]["method"] = "GET"
    local_seen = []

    def local_evaluator(evidence, context):
        local_seen.append((evidence.url, context.hints["target_url"]))
        return TrustDecision(is_trusted=True, reason="local raw check")

    remote = RemoteTrustEvaluator(endpoint_url="https://advisor.test/trust")
    client = Payment402Client(trust_evaluators=[local_evaluator, remote])
    context = ExecutionContext(
        hints={
            "target_url": wire_url,
            "agent_id": "public-agent-123",
            "public_hint": "public-advisory-value",
            "allowed_hosts": ["public.example"],
            "api_key": "remote-hint-api-secret",
            "nested": {"reset_code": "remote-hint-reset-code"},
        }
    )
    remote_response = MagicMock()
    remote_response.ok = True
    remote_response.json.return_value = {
        "recommendation": "deny",
        "reason": "test stop before signing",
    }

    with patch(
        "ln_church_agent.evaluators.requests.post",
        return_value=remote_response,
    ) as remote_post:
        if async_mode:
            async def run():
                client._async_client = MagicMock()
                client._async_client.request = AsyncMock(
                    return_value=_exact_402(challenge, url=wire_url)
                )
                with pytest.raises(CounterpartyTrustError):
                    await client.execute_detailed_async(
                        "GET", "https://buyer.test/start",
                        payload=query, context=context,
                    )
                return client._async_client.request

            transport = asyncio.run(run())
        else:
            with patch(
                "ln_church_agent.client.requests.request",
                return_value=_exact_402(challenge, url=wire_url),
            ) as transport:
                with pytest.raises(CounterpartyTrustError):
                    client.execute_detailed(
                        "GET", "https://buyer.test/start",
                        payload=query, context=context,
                    )

    assert transport.call_args.args[1] == wire_url
    assert local_seen == [(wire_url, wire_url)]
    remote_payload = remote_post.call_args.kwargs["json"]
    assert set(
        value
        for values in parse_qs(
            urlparse(remote_payload["target_url"]).query
        ).values()
        for value in values
    ) == {"REDACTED"}
    assert remote_payload["context"]["hints"]["api_key"] == "REDACTED"
    assert (
        remote_payload["context"]["hints"]["nested"]["reset_code"]
        == "REDACTED"
    )
    assert remote_payload["context"]["agent_id"] == "public-agent-123"
    assert (
        remote_payload["context"]["hints"]["public_hint"]
        == "public-advisory-value"
    )
    assert remote_payload["context"]["hints"]["allowed_hosts"] == [
        "public.example"
    ]
    assert "remote-trust-" not in json.dumps(remote_payload)
    assert context.hints["target_url"] == wire_url
    assert context.hints["api_key"] == "remote-hint-api-secret"
    assert (
        client._last_parsed_challenge._canonical_requirement["resource_url"]
        == wire_url
    )


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_remote_outcome_redacts_query_but_local_and_result_stay_raw(
    async_mode,
):
    query = {
        "api_key": "remote-outcome-api-secret",
        "X-Goog-Signature": "remote-outcome-presigned-secret",
        "q": "remote-outcome-private-query",
    }
    probe = Payment402Client()
    wire_url = probe._final_wire_url(
        "GET", "https://buyer.test/start", query
    )
    local_seen = []

    def local_matcher(response, receipt, context):
        local_seen.append(context.hints["target_url"])
        return OutcomeSummary(
            is_success=True,
            observed_state="local-raw-verified",
            message="local",
        )

    matcher = RemoteOutcomeMatcher(
        endpoint_url="https://advisor.test/outcome",
        local_fallback_matcher=local_matcher,
    )
    context = ExecutionContext(
        hints={
            "agent_id": "public-outcome-agent",
            "api_key": "local-only-secret",
        }
    )
    response = _transport_response(
        200, {"status": "ok"}, url=wire_url
    )
    remote_response = MagicMock()
    remote_response.ok = True
    remote_response.json.return_value = {
        "recommended_success": True,
        "observed_state": "remote",
    }

    with patch(
        "ln_church_agent.evaluators.requests.post",
        return_value=remote_response,
    ) as remote_post:
        if async_mode:
            async def run():
                client = Payment402Client()
                client._async_client = MagicMock()
                client._async_client.request = AsyncMock(
                    return_value=response
                )
                result = await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", payload=query,
                    context=context, outcome_matcher=matcher,
                )
                return result, client._async_client.request

            result, transport = asyncio.run(run())
        else:
            client = Payment402Client()
            with patch(
                "ln_church_agent.client.requests.request",
                return_value=response,
            ) as transport:
                result = client.execute_detailed(
                    "GET", "https://buyer.test/start", payload=query,
                    context=context, outcome_matcher=matcher,
                )

    assert transport.call_args.args[1] == wire_url
    assert result.final_url == wire_url
    assert local_seen == [wire_url]
    assert context.hints["target_url"] == wire_url
    remote_payload = remote_post.call_args.kwargs["json"]
    assert remote_payload["context"]["agent_id"] == "public-outcome-agent"
    assert set(
        value
        for values in parse_qs(
            urlparse(remote_payload["target_url"]).query
        ).values()
        for value in values
    ) == {"REDACTED"}
    assert "remote-outcome-" not in json.dumps(remote_payload)


def test_audit_get_query_resource_mismatch_stops_before_signing():
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_exact_402(),
    ) as transport, patch.object(
        client.evm_signer, "generate_eip3009_payload_atomic"
    ) as signer:
        with pytest.raises(PaymentExecutionError, match="resource.url"):
            client.execute_detailed(
                "GET", "https://buyer.test/start", payload={"q": "different"}
            )
    assert transport.call_count == 1
    signer.assert_not_called()
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == 0


def test_audit_receipt_identity_changes_with_logical_operation():
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=[
            _exact_402(),
            _transport_response(200, {"operation": 1}),
            _exact_402(),
            _transport_response(200, {"operation": 2}),
        ],
    ):
        first = client.execute_detailed(
            "GET",
            "https://buyer.test/start",
            headers={"Idempotency-Key": "logical-operation-1"},
            context=ExecutionContext(),
        )
        second = client.execute_detailed(
            "GET",
            "https://buyer.test/start",
            headers={"Idempotency-Key": "logical-operation-2"},
            context=ExecutionContext(),
        )

    assert first.settlement_receipt.receipt_id != second.settlement_receipt.receipt_id
    assert (
        first.settlement_receipt.proof_reference
        != second.settlement_receipt.proof_reference
    )


def test_audit_parallel_budget_check_and_reserve_is_atomic_across_contexts():
    policy = PaymentPolicy(max_spend_per_session_usd=1.5)
    client = Payment402Client(policy=policy)
    barrier = threading.Barrier(2)

    def reserve(index):
        context = ExecutionContext(session_id="shared-session")
        barrier.wait(timeout=5)
        try:
            client._reserve_session_budget(context, f"operation-{index}", "1")
        except PaymentExecutionError:
            return context, False
        return context, True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, (1, 2)))

    assert sum(success for _context, success in results) == 1
    assert policy._session_spent_usd == 0
    assert policy._session_reserved_usd == pytest.approx(1.0)
    winner_context, _ = next(item for item in results if item[1])
    fingerprint = next(iter(winner_context._budget_reservations))
    client._confirm_session_budget(winner_context, fingerprint)
    assert policy._session_spent_usd == pytest.approx(1.0)
    assert policy._session_reserved_usd == 0


def test_audit_policy_lock_is_out_of_band_for_asdict_and_deepcopy():
    policy = PaymentPolicy(max_spend_per_session_usd=2.0)
    serialized = asdict(policy)
    cloned = copy.deepcopy(policy)
    assert "_session_spend_lock" not in serialized
    assert "_restored_session_ids" not in serialized
    json.dumps(serialized)
    assert cloned._session_spend_lock is not policy._session_spend_lock
    assert cloned.max_spend_per_session_usd == 2.0


def test_audit_restore_merges_distinct_concurrent_confirmation():
    entered = threading.Event()
    release_import = threading.Event()

    class BlockingRepo(EvidenceRepository):
        def import_session_evidence(self, context):
            entered.set()
            assert release_import.wait(timeout=5)
            return [
                PaymentEvidenceRecord(
                    session_id=context.session_id,
                    correlation_id="historical",
                    target_url="https://buyer.test/history",
                    method="GET",
                    session_spend_delta_usd=4.0,
                    receipt_summary={"receipt_id": "historical-receipt"},
                )
            ]

    policy = PaymentPolicy(max_spend_per_session_usd=10.0)
    client = Payment402Client(policy=policy, evidence_repo=BlockingRepo())
    restoring = ExecutionContext(session_id="shared-session")
    concurrent = ExecutionContext(session_id="shared-session")

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(client._restore_session_spend_from_evidence, restoring)
        assert entered.wait(timeout=5)
        client._reserve_session_budget(concurrent, "concurrent", "3")
        client._confirm_session_budget(concurrent, "concurrent")
        release_import.set()
        future.result(timeout=5)

    assert policy._session_spent_usd == pytest.approx(7.0)
    assert policy._session_reserved_usd == 0


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "event_state", ["confirmed", "reserved"],
    ids=["confirmed", "reserved"],
)
def test_audit_restore_deduplicates_same_concurrent_operation(
    async_mode, event_state
):
    entered = threading.Event()
    release_import = threading.Event()

    class BlockingJournalRepo(EvidenceRepository):
        def __init__(self):
            self.records = []

        def _records_after_concurrent_export(self):
            entered.set()
            assert release_import.wait(timeout=5)
            return list(self.records)

        def import_session_evidence(self, context):
            return self._records_after_concurrent_export()

        async def import_session_evidence_async(self, context):
            return self._records_after_concurrent_export()

    operation_id = "same-concurrent-operation"
    repo = BlockingJournalRepo()
    policy = PaymentPolicy(max_spend_per_session_usd=10.0)
    client = Payment402Client(policy=policy, evidence_repo=repo)
    restoring = ExecutionContext(session_id="shared-overlap-session")
    concurrent = ExecutionContext(session_id="shared-overlap-session")

    def restore():
        if async_mode:
            asyncio.run(
                client._restore_session_spend_from_evidence_async(restoring)
            )
        else:
            client._restore_session_spend_from_evidence(restoring)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(restore)
        assert entered.wait(timeout=5)
        client._reserve_session_budget(concurrent, operation_id, "3")
        if event_state == "confirmed":
            client._confirm_session_budget(concurrent, operation_id)
        else:
            client._mark_session_budget_unknown(concurrent, operation_id)
        repo.records = [
            PaymentEvidenceRecord(
                session_id=restoring.session_id,
                correlation_id="concurrent-export",
                target_url="https://buyer.test/start",
                method="GET",
                session_spend_delta_usd=(
                    3.0 if event_state == "confirmed" else 0.0
                ),
                session_budget_event=event_state,
                session_budget_operation_id=operation_id,
                session_budget_amount_usd=3.0,
            )
        ]
        release_import.set()
        future.result(timeout=5)

    if event_state == "confirmed":
        assert policy._session_spent_usd == pytest.approx(3.0)
        assert policy._session_reserved_usd == 0
    else:
        assert policy._session_spent_usd == 0
        assert policy._session_reserved_usd == pytest.approx(3.0)
        assert restoring._ambiguous_reservations[operation_id] == Decimal("3.0")
        assert restoring.get_payment_state(operation_id) == "settlement_unknown"


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_restore_uses_operation_version_across_reserved_aba(async_mode):
    entered = threading.Event()
    release_import = threading.Event()

    class AbaRepo(EvidenceRepository):
        def _import(self):
            entered.set()
            assert release_import.wait(timeout=5)
            return [
                PaymentEvidenceRecord(
                    session_id="aba-session",
                    correlation_id="stale-middle-snapshot",
                    target_url="https://buyer.test/start",
                    method="GET",
                    session_spend_delta_usd=0.0,
                    session_budget_event="released",
                    session_budget_operation_id="aba-operation",
                    session_budget_amount_usd=3.0,
                )
            ]

        def import_session_evidence(self, context):
            return self._import()

        async def import_session_evidence_async(self, context):
            return self._import()

    policy = PaymentPolicy(max_spend_per_session_usd=10.0)
    client = Payment402Client(policy=policy, evidence_repo=AbaRepo())
    owner = ExecutionContext(session_id="aba-session")
    restoring = ExecutionContext(session_id="aba-session")
    client._reserve_session_budget(owner, "aba-operation", "3")

    def restore():
        if async_mode:
            asyncio.run(
                client._restore_session_spend_from_evidence_async(restoring)
            )
        else:
            client._restore_session_spend_from_evidence(restoring)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(restore)
        assert entered.wait(timeout=5)
        assert client._release_session_budget(
            owner, "aba-operation"
        ) == Decimal("3")
        assert client._reserve_session_budget(
            owner, "aba-operation", "3"
        ) == Decimal("3")
        release_import.set()
        future.result(timeout=5)

    assert policy._session_spent_usd == 0
    assert policy._session_reserved_usd == pytest.approx(3.0)
    assert restoring._ambiguous_reservations["aba-operation"] == Decimal("3.0")


def test_audit_duplicate_context_cannot_cancel_or_confirm_owner_reservation():
    client = Payment402Client(
        policy=PaymentPolicy(max_spend_per_session_usd=10.0)
    )
    owner = ExecutionContext(session_id="owner-session")
    duplicate = ExecutionContext(session_id="owner-session")
    operation_id = "owned-operation"

    client._reserve_session_budget(owner, operation_id, "3")
    with pytest.raises(PaymentExecutionError, match="already reserved"):
        client._reserve_session_budget(duplicate, operation_id, "3")
    assert client._release_session_budget(duplicate, operation_id) == 0
    with pytest.raises(PaymentExecutionError, match="does not own"):
        client._confirm_session_budget(duplicate, operation_id)
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == pytest.approx(3.0)

    assert client._confirm_session_budget(
        owner, operation_id
    ) == Decimal("3")
    assert client.policy._session_spent_usd == pytest.approx(3.0)
    assert client.policy._session_reserved_usd == 0


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "first_outcome", ["confirmed_paid", "confirmed_not_paid"],
    ids=["paid", "not-paid"],
)
def test_audit_hydrated_contexts_cannot_resolve_one_reservation_twice(
    async_mode, first_outcome
):
    operation_id = "hydrated-shared-operation"
    evidence = _PersistentEvidence()
    evidence.records = [
        PaymentEvidenceRecord(
            session_id="hydrated-session",
            correlation_id="reservation",
            target_url="https://buyer.test/start",
            method="GET",
            session_spend_delta_usd=0.0,
            session_budget_event="reserved",
            session_budget_operation_id=operation_id,
            session_budget_amount_usd=3.0,
        )
    ]
    client = Payment402Client(
        policy=PaymentPolicy(max_spend_per_session_usd=10.0),
        evidence_repo=evidence,
    )
    first = ExecutionContext(session_id="hydrated-session")
    stale = ExecutionContext(session_id="hydrated-session")
    client._restore_session_spend_from_evidence(first)
    client._restore_session_spend_from_evidence(stale)

    if async_mode:
        asyncio.run(
            client.resolve_ambiguous_payment_async(
                first, operation_id, first_outcome
            )
        )
    else:
        client.resolve_ambiguous_payment(first, operation_id, first_outcome)

    with pytest.raises(PaymentExecutionError, match="already resolved"):
        client.resolve_ambiguous_payment(stale, operation_id, first_outcome)
    conflicting = (
        "confirmed_not_paid"
        if first_outcome == "confirmed_paid" else "confirmed_paid"
    )
    with pytest.raises(PaymentExecutionError):
        client.resolve_ambiguous_payment(stale, operation_id, conflicting)

    expected_spent = 3.0 if first_outcome == "confirmed_paid" else 0.0
    assert client.policy._session_spent_usd == pytest.approx(expected_spent)
    assert client.policy._session_reserved_usd == 0


def test_audit_signed_receipt_without_settlement_checker_stays_unsettled():
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    verified_claims = {}

    def transport(_method, _url, **_kwargs):
        if not verified_claims:
            return _exact_402()
        token = ".".join(
            (
                _encode_requirement({"alg": "test"}),
                _encode_requirement(verified_claims),
                "AA",
            )
        )
        return _transport_response(
            200,
            {"status": "paid"},
            headers={"PAYMENT-RESPONSE": token},
        )

    def signature_verifier(_token):
        return dict(verified_claims)

    client._receipt_signature_verifier = signature_verifier

    call_count = 0
    def dynamic_transport(method, url, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            response = _exact_402()
            original_json = response.json
            # The verifier claims are filled after parsing/signing, before the
            # second transport call.
            return response
        requirement = client._last_parsed_challenge._canonical_requirement
        verified_claims.update(
            {
                "payment_id": requirement["payment_id"],
                "requirement_hash": requirement["requirement_hash"],
            }
        )
        return transport(method, url, **kwargs)

    with patch(
        "ln_church_agent.client.requests.request",
        side_effect=dynamic_transport,
    ):
        result = client.execute_detailed("GET", "https://buyer.test/start")

    receipt = result.settlement_receipt
    assert receipt.signature_verified is True
    assert receipt.settlement_verified is False
    assert receipt.verification_status == "signature_verified"


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_audit_exact_credential_redirect_cannot_confirm_settlement(async_mode):
    client = Payment402Client(private_key=EVM_PRIVATE_KEY)
    context = ExecutionContext(hints={"allowed_hosts": ["public.test"]})
    redirect = _transport_response(
        302,
        headers={"Location": "https://public.test/free"},
        url="https://buyer.test/start",
    )
    public_success = _transport_response(
        200, {"status": "free"}, url="https://public.test/free"
    )

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(
                side_effect=[_exact_402(), redirect, public_success]
            )
            with pytest.raises(PaymentExecutionError, match="settlement_unknown"):
                await client.execute_detailed_async(
                    "GET", "https://buyer.test/start", context=context
                )
            assert client._async_client.request.call_count == 2

        asyncio.run(run())
    else:
        with patch(
            "ln_church_agent.client.requests.request",
            side_effect=[_exact_402(), redirect, public_success],
        ) as transport:
            with pytest.raises(PaymentExecutionError, match="settlement_unknown"):
                client.execute_detailed(
                    "GET", "https://buyer.test/start", context=context
                )
        assert transport.call_count == 2

    assert set(context._payment_states.values()) == {"settlement_unknown"}
    assert client.policy._session_spent_usd == 0
    assert client.policy._session_reserved_usd == pytest.approx(1.0)
    assert client.last_receipt.payment_performed is False
