import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import NavigationGuardrailError
from ln_church_agent.models import ExecutionContext, PaymentPolicy


def _response(status, *, location=None, body=None):
    response = MagicMock()
    response.status_code = status
    response.headers = {"Location": location} if location else {}
    response.content = b"{}"
    response.json.return_value = body if body is not None else {"status": "ok"}
    return response


@pytest.mark.parametrize(
    "target,error",
    [
        ("http://public.test/next", "downgrade"),
        ("https://127.0.0.1/next", "non-public"),
        ("https://169.254.169.254/latest", "non-public"),
        ("https://[::1]/next", "non-public"),
        ("https://public.test:22/next", "port"),
        ("file:///etc/passwd", "HTTP or HTTPS"),
        ("https://user@public.test/next", "userinfo"),
    ],
)
def test_unsafe_redirect_is_rejected_before_second_transport(target, error):
    client = Payment402Client(base_url="https://public.test")
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_response(302, location=target),
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match=error):
            client.execute_detailed("GET", "/start")
    assert transport.call_count == 1


def test_mixed_public_private_dns_answers_fail_closed():
    client = Payment402Client(base_url="https://public.test")
    client._navigation_resolver = lambda _host, _port: (
        "93.184.216.34",
        "10.0.0.7",
    )
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_response(302, location="https://other.test/next"),
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match="non-public"):
            client.execute_detailed(
                "GET",
                "/start",
                context=ExecutionContext(hints={"allowed_hosts": ["other.test"]}),
            )
    assert transport.call_count == 1


def test_redirect_loop_is_rejected_before_revisiting_initial_url():
    client = Payment402Client(base_url="https://public.test", max_hops=5)
    responses = [
        _response(302, location="/two"),
        _response(302, location="/start"),
    ]
    with patch(
        "ln_church_agent.client.requests.request", side_effect=responses
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match="loop"):
            client.execute_detailed("GET", "/start")
    assert transport.call_count == 2


def test_redirect_hop_limit_is_checked_before_extra_transport():
    client = Payment402Client(base_url="https://public.test", max_hops=1)
    responses = [
        _response(302, location="/two"),
        _response(302, location="/three"),
    ]
    with patch(
        "ln_church_agent.client.requests.request", side_effect=responses
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match="hop limit"):
            client.execute_detailed("GET", "/start")
    assert transport.call_count == 2


def test_same_origin_keeps_wire_idempotency_but_strips_payment_credentials():
    client = Payment402Client(base_url="https://public.test", max_hops=2)
    responses = [_response(302, location="/two"), _response(200)]
    with patch(
        "ln_church_agent.client.requests.request", side_effect=responses
    ) as transport:
        client.execute_detailed(
            "GET",
            "/start",
            headers={
                "Idempotency-Key": "purchase-1",
                "Authorization": "L402 secret:secret",
                "PAYMENT-SIGNATURE": "secret",
            },
        )
    second_headers = transport.call_args_list[1].kwargs["headers"]
    assert second_headers["Idempotency-Key"] == "purchase-1"
    assert "Authorization" not in second_headers
    assert "PAYMENT-SIGNATURE" not in second_headers


def test_cross_origin_derives_key_and_never_forwards_source_credentials():
    client = Payment402Client(base_url="https://public.test", max_hops=2)
    context = ExecutionContext(hints={"allowed_hosts": ["other.test"]})
    responses = [
        _response(302, location="https://other.test/two"),
        _response(200),
    ]
    with patch(
        "ln_church_agent.client.requests.request", side_effect=responses
    ) as transport:
        client.execute_detailed(
            "GET",
            "/start",
            headers={
                "Idempotency-Key": "purchase-1",
                "Authorization": "Bearer secret",
                "X-PAYMENT": "secret",
                "Cookie": "secret=yes",
            },
            context=context,
        )
    second_headers = transport.call_args_list[1].kwargs["headers"]
    assert second_headers["Idempotency-Key"].startswith("lnc_")
    assert second_headers["Idempotency-Key"] != "purchase-1"
    assert "Authorization" not in second_headers
    assert "X-PAYMENT" not in second_headers
    assert "Cookie" not in second_headers


def test_redirect_target_local_host_policy_is_rechecked_before_transport():
    policy = PaymentPolicy(allowed_hosts=["public.test"])
    client = Payment402Client(base_url="https://public.test", policy=policy)
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=_response(302, location="https://other.test/two"),
    ) as transport:
        with pytest.raises(NavigationGuardrailError, match="allowed_hosts"):
            client.execute_detailed(
                "GET",
                "/start",
                context=ExecutionContext(hints={"allowed_hosts": ["other.test"]}),
            )
    assert transport.call_count == 1


def test_redirect_transport_uses_public_dns_pin_with_original_host_and_sni():
    wallet = MagicMock()
    client = Payment402Client(
        base_url="https://public.test", ln_adapter=wallet, max_hops=2
    )
    context = ExecutionContext(hints={"allowed_hosts": ["other.test"]})
    client._navigation_resolver = lambda _host, _port: ("93.184.216.34",)
    responses = [
        _response(302, location="https://other.test/next"),
        _response(200),
    ]

    with patch(
        "ln_church_agent.client.requests.request", side_effect=responses
    ) as transport:
        client.execute_detailed("GET", "/start", context=context)

    second = transport.call_args_list[1]
    assert second.args[1] == "https://93.184.216.34/next"
    assert second.kwargs["headers"]["Host"] == "other.test"
    assert "10.0.0.7" not in second.args[1]
    wallet.pay_invoice.assert_not_called()


def test_async_redirect_transport_uses_public_dns_pin_with_original_host_and_sni():
    async def run():
        wallet = MagicMock()
        client = Payment402Client(
            base_url="https://public.test", ln_adapter=wallet, max_hops=2
        )
        context = ExecutionContext(hints={"allowed_hosts": ["other.test"]})
        client._navigation_resolver = lambda _host, _port: ("93.184.216.34",)
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            side_effect=[
                _response(302, location="https://other.test/next"),
                _response(200),
            ]
        )

        await client.execute_detailed_async("GET", "/start", context=context)

        second = client._async_client.request.call_args_list[1]
        assert second.args[1] == "https://93.184.216.34/next"
        assert second.kwargs["headers"]["Host"] == "other.test"
        assert second.kwargs["extensions"]["sni_hostname"] == "other.test"
        assert "10.0.0.7" not in second.args[1]
        wallet.pay_invoice.assert_not_called()

    asyncio.run(run())
