import base64
import json

from ln_church_agent.receipts import ReceiptState, evaluate_payment_receipt


def _b64url(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jws(claims):
    return ".".join((_b64url({"alg": "test", "typ": "JWT"}), _b64url(claims), _b64url("sig")))


def test_no_receipt_keeps_delivery_independent():
    state = evaluate_payment_receipt({}, 204)

    assert state == ReceiptState(
        present=False,
        server_asserted=False,
        signature_verified=False,
        settlement_verified=False,
        delivered=True,
    )


def test_unsigned_base64url_json_is_asserted_but_never_verified():
    claims = {"payment_id": "pay-1", "settled": True}
    token = _b64url(claims)

    state = evaluate_payment_receipt(
        {"PAYMENT-RESPONSE": token},
        503,
        signature_verifier=lambda value: claims,
        settlement_binding_checker=lambda value: True,
    )

    assert state.present is True
    assert state.server_asserted is True
    assert state.signature_verified is False
    assert state.settlement_verified is False
    assert state.delivered is False
    assert state.format == "unsigned_base64json"
    assert state.claims == claims


def test_standard_base64_json_is_accepted_with_explicit_unsigned_format():
    claims = {"receipt": "+/"}
    token = base64.b64encode(json.dumps(claims).encode("utf-8")).decode("ascii")

    state = evaluate_payment_receipt({"Payment-Receipt": token}, 200)

    assert state.server_asserted is True
    assert state.format == "unsigned_base64json"
    assert state.signature_verified is False
    assert state.settlement_verified is False


def test_malformed_or_non_object_payload_is_present_but_not_asserted():
    malformed = evaluate_payment_receipt({"Payment-Receipt": "%%%"}, 200)
    array_token = _b64url(["not", "an", "object"])
    non_object = evaluate_payment_receipt({"payment-response": array_token}, 200)

    for state in (malformed, non_object):
        assert state.present is True
        assert state.server_asserted is False
        assert state.signature_verified is False
        assert state.settlement_verified is False
        assert state.error == "malformed_receipt"


def test_conflicting_receipt_headers_fail_closed_without_disclosing_tokens():
    first = _b64url({"payment_id": "secret-one"})
    second = _b64url({"payment_id": "secret-two"})

    state = evaluate_payment_receipt(
        {"PAYMENT-RESPONSE": first, "Payment-Receipt": second}, 200
    )

    assert state.present is True
    assert state.server_asserted is False
    assert state.error == "conflicting_receipt_headers"
    assert state.token is None
    assert first not in repr(state)
    assert second not in repr(state)


def test_equal_values_across_both_headers_are_one_receipt():
    token = _b64url({"payment_id": "pay-2"})

    state = evaluate_payment_receipt(
        {
            "PAYMENT-RESPONSE": f'status="success", receipt="{token}"',
            "payment-receipt": token,
        },
        201,
    )

    assert state.server_asserted is True
    assert state.delivered is True


def test_structural_jws_without_verifier_is_not_signature_verified():
    claims = {"payment_id": "pay-3", "exp": 2_000_000_000}
    token = _jws(claims)

    state = evaluate_payment_receipt({"Payment-Receipt": token}, 200)

    assert state.server_asserted is True
    assert state.signature_verified is False
    assert state.settlement_verified is False
    assert state.format == "jws"
    assert state.error is None


def test_jws_signature_and_settlement_bindings_remain_separate():
    claims = {"payment_id": "pay-4", "requirement_hash": "sha256:abc"}
    token = _jws(claims)

    signed_only = evaluate_payment_receipt(
        {"Payment-Receipt": token},
        200,
        signature_verifier=lambda value: claims,
    )
    fully_verified = evaluate_payment_receipt(
        {"Payment-Receipt": token},
        500,
        signature_verifier=lambda value: claims,
        settlement_binding_checker=lambda value: value["requirement_hash"] == "sha256:abc",
    )

    assert signed_only.signature_verified is True
    assert signed_only.settlement_verified is False
    assert signed_only.delivered is True
    assert fully_verified.signature_verified is True
    assert fully_verified.settlement_verified is True
    assert fully_verified.delivered is False


def test_wrong_key_expired_or_binding_failure_never_becomes_verified():
    claims = {"payment_id": "pay-5"}
    token = _jws(claims)

    returned_none = evaluate_payment_receipt(
        {"Payment-Receipt": token}, 200, signature_verifier=lambda value: None
    )

    def expired(_value):
        raise ValueError("expired: token contents must not reach the state error")

    raised = evaluate_payment_receipt(
        {"Payment-Receipt": token}, 200, signature_verifier=expired
    )
    binding_failed = evaluate_payment_receipt(
        {"Payment-Receipt": token},
        200,
        signature_verifier=lambda value: claims,
        settlement_binding_checker=lambda value: False,
    )

    assert returned_none.signature_verified is False
    assert returned_none.error == "signature_verification_failed"
    assert raised.signature_verified is False
    assert raised.error == "signature_verification_failed"
    assert "expired" not in repr(raised)
    assert binding_failed.signature_verified is True
    assert binding_failed.settlement_verified is False
    assert binding_failed.error == "settlement_verification_failed"


def test_duplicate_json_keys_and_invalid_jws_are_malformed():
    duplicate = base64.urlsafe_b64encode(b'{"id":"one","id":"two"}').decode().rstrip("=")
    invalid_jws = _b64url({"alg": "test"}) + "." + _b64url({"id": "one"}) + ".***"

    duplicate_state = evaluate_payment_receipt({"Payment-Receipt": duplicate}, 200)
    jws_state = evaluate_payment_receipt({"Payment-Receipt": invalid_jws}, 200)

    assert duplicate_state.server_asserted is False
    assert duplicate_state.error == "malformed_receipt"
    assert jws_state.server_asserted is False
    assert jws_state.error == "malformed_receipt"


def test_token_and_claims_are_not_in_state_repr():
    claims = {"sensitive": "do-not-log"}
    token = _b64url(claims)

    state = evaluate_payment_receipt({"Payment-Receipt": token}, 200)

    assert token not in repr(state)
    assert "do-not-log" not in repr(state)
