import pytest
import io
import sys
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient, validate_public_domain_for_observation
from ln_church_agent.models import DomainObservationSlotResponse, DomainObservationResultSubmission

def test_public_import():
    try:
        from ln_church_agent import validate_public_domain_for_observation
        assert callable(validate_public_domain_for_observation)
    except ImportError as e:
        pytest.fail(f"Public import failed: {e}")

def test_validate_public_domain_for_observation():
    assert validate_public_domain_for_observation("example.com") is True
    assert validate_public_domain_for_observation("api.v2.example-domain.org") is True

    assert validate_public_domain_for_observation("localhost") is False
    assert validate_public_domain_for_observation("127.0.0.1") is False
    assert validate_public_domain_for_observation("10.0.0.5") is False
    assert validate_public_domain_for_observation("169.254.169.254") is False
    assert validate_public_domain_for_observation("metadata.google.internal") is False

    assert validate_public_domain_for_observation("https://example.com") is False
    assert validate_public_domain_for_observation("example.com:8080") is False
    assert validate_public_domain_for_observation("example.com/path") is False

@patch("ln_church_agent.client.Payment402Client.execute_detailed")
def test_register_domain_observation_slot(mock_exec):
    mock_res = MagicMock()
    mock_res.response = {
        "request_id": "obsreq_123",
        "domain": "example.com",
        "status": "accepted",
        "requester_paid": True,
        "domain_owner_verified": False,
        "sponsor_verified": False,
        "sponsor_type": "paid_observation_slot",
        "duration_days": 7,
        "observation_profile": "public_safe_light"
    }
    mock_res.response_headers = {
        "X-LN-Result-Handle": "paidres_123",
        "X-LN-Request-Hash": "hash123"
    }
    mock_exec.return_value = mock_res

    client = LnChurchClient(private_key="0x" + "1"*64)
    res = client.register_domain_observation_slot("example.com", idempotency_key="idm_abc")

    assert res.request_id == "obsreq_123"
    assert res.requester_paid is True
    assert res.result_handle == "paidres_123"  # ヘッダーからの抽出

    args, kwargs = mock_exec.call_args
    assert args[1] == "/api/bazaar/domain-observation-slots"
    assert kwargs["payload"]["domain"] == "example.com"
    assert kwargs["headers"]["Idempotency-Key"] == "idm_abc"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_get_domain_observation_request_path(mock_req):
    client = LnChurchClient(agent_id="test_worker")
    mock_req.return_value = {"request_id": "obsreq_123", "domain": "example.com", "status": "active"}

    res = client.get_domain_observation_request("obsreq_123")
    assert res.request_id == "obsreq_123"
    assert mock_req.call_args[0][1] == "/api/agent/external/observatory/domain-observation-requests/obsreq_123"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_get_domain_observation_read_model_path(mock_req):
    client = LnChurchClient(agent_id="test_worker")
    mock_req.return_value = {"domain": "example.com", "observation_requests": []}

    res = client.get_domain_observation_read_model("example.com")
    assert res.domain == "example.com"
    assert mock_req.call_args[0][1] == "/api/agent/external/observatory/domains/example.com"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_claim_domain_observation_targets_success(mock_req):
    client = LnChurchClient(agent_id="test_worker")
    mock_req.return_value = {"targets": [{"target_id": "tgt_1", "request_id": "req_1", "domain": "example.com"}]}

    res = client.claim_domain_observation_targets(observer="openclaw", limit=3, internal_secret="sec")

    assert len(res.targets) == 1
    assert "observer=openclaw" in mock_req.call_args[0][1]
    assert "limit=3" in mock_req.call_args[0][1]
    assert mock_req.call_args[1]["headers"]["X-Internal-Secret"] == "sec"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_internal_observatory_worker_target_claim_auth_guard(mock_req):
    client = LnChurchClient(agent_id="test_worker")
    with pytest.raises(ValueError, match="LN_CHURCH_INTERNAL_SECRET is required"):
        client.claim_domain_observation_targets()

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_submit_domain_observation_result_success(mock_req):
    client = LnChurchClient(agent_id="test_worker")
    mock_req.return_value = {"accepted": True, "request_id": "req_1", "target_id": "tgt_1", "observation_id": "obs_1", "status": "recorded"}

    submission = DomainObservationResultSubmission(target_id="tgt_1", request_id="req_1", observed_domain="example.com")
    res = client.submit_domain_observation_result(submission, internal_secret="sec")

    assert res.status == "recorded"
    assert mock_req.call_args[0][1] == "/api/agent/external/domain-observation-results"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_submit_observation_result_client_side_guardrails(mock_req):
    client = LnChurchClient(agent_id="test_worker")

    bad_submission_1 = DomainObservationResultSubmission(
        target_id="tgt_1", request_id="req_1", observed_domain="example.com"
    )
    bad_submission_1.verification_cost_vector["payment_attempts"] = 1

    with pytest.raises(ValueError, match="payment_attempts must be 0"):
        client.submit_domain_observation_result(bad_submission_1, internal_secret="secret")

    bad_submission_2 = DomainObservationResultSubmission(
        target_id="tgt_1", request_id="req_1", observed_domain="example.com"
    )
    bad_submission_2.verification_cost_vector["irreversible_action_attempted"] = True

    with pytest.raises(ValueError, match="irreversible_action_attempted is not allowed"):
        client.submit_domain_observation_result(bad_submission_2, internal_secret="secret")

@patch("sys.stdout", new_callable=io.StringIO)
def test_cli_register_without_pay(mock_stdout):
    from ln_church_agent.cli import main
    with patch.object(sys, 'argv', ["ln-church-agent", "observe-domain", "register", "example.com", "--private-key", "0x123"]):
        main()
        assert "Use '--pay' to explicitly acknowledge" in mock_stdout.getvalue()

@patch("sys.stdout", new_callable=io.StringIO)
@patch("ln_church_agent.client.LnChurchClient.claim_domain_observation_targets")
def test_cli_observatory_does_not_leak_secret(mock_claim, mock_stdout):
    mock_claim.return_value = MagicMock(targets=[])
    from ln_church_agent.cli import main
    with patch.object(sys, 'argv', ["ln-church-agent", "observatory", "targets", "claim", "--internal-secret", "SUPER_SECRET_123"]):
        main()
        output = mock_stdout.getvalue()
        assert "SUPER_SECRET_123" not in output
        assert "Claimed" in output
