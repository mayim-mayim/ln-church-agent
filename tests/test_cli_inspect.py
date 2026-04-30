import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url
import requests

@patch("ln_church_agent.cli.requests.request")
def test_inspect_l402_pay_and_verify(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "pay_and_verify"
    assert "L402" in res.rails_detected
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_mpp_charge_pay_and_verify(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'MPP invoice="inv", intent="charge"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "pay_and_verify"
    assert res.payment_intent == "charge"
    assert "MPP" in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_mpp_session_stop_safely(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'MPP invoice="inv", intent="session"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "stop_safely"
    assert res.payment_intent == "session"

@patch("ln_church_agent.cli.requests.request")
def test_inspect_200_no_payment_required(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.content = b""
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "no_payment_required"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_network_exception(mock_req):
    mock_req.side_effect = requests.exceptions.ConnectionError("Failed to connect")

    res = inspect_url("http://test.local")
    assert res.ok is False
    assert res.recommended_action == "stop_safely"
    assert res.error_stage == "fetch"
    assert "Failed to connect" in res.failure_reason

@patch("ln_church_agent.cli.requests.request")
def test_inspect_invalid_challenge_reject_invalid(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'UnknownScheme invalid="data"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "reject_invalid"
    assert "Failed to parse challenge" in res.reason