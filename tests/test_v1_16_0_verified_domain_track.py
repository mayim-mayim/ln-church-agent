import pytest
from unittest.mock import patch, MagicMock
import io
import sys
import os
import json
from ln_church_agent.client import LnChurchClient
from ln_church_agent.models import (
    PaymentPolicy,
    VerifiedDomainTrackRegistrationResponse,
    VerifiedDomainTrackReadModel,
    VerifiedDomainTrackSummary,
    DomainObservationDomainReadModel
)

# [品質改善] 安定性の高い private key の定義
STABLE_PRIVATE_KEY = "0x" + "1" * 64

def test_v1_16_0_models_can_be_imported():
    assert VerifiedDomainTrackRegistrationResponse
    assert VerifiedDomainTrackReadModel
    assert VerifiedDomainTrackSummary

def test_verified_domain_track_read_model_parsing():
    mock_data = {
        "domain": "kari.mayim-mayim.com",
        "sponsor_type": "verified_domain_track",
        "track_type": "verified_domain_track",
        "track_plan": "verified_domain_track_lite",
        "track_status": "active_verified",
        "duration_days": 30,
        "observation_interval_hours": 168,
        "observation_profile": "public_safe_light",
        "verification_required": True,
        "domain_owner_verified": False,
        "sponsor_verified": True,
        "domain_control_verified": True,
        "sponsor_verification_status": "verified",
        "verification_scope": "domain_control_not_legal_ownership",
        "not_legal_ownership_proof": True,
        "is_active_verified_track": True,
        "created_at": "2026-07-01T12:00:00Z",
        "expires_at": "2026-07-31T12:00:00Z",
        "not_a_verdict": True,
        "not_a_security_scan": True,
        "not_an_endorsement": True,
        "not_a_certification": True,
        "not_a_recommendation": True,
        "not_a_trust_score": True
    }
    model = VerifiedDomainTrackReadModel(**mock_data)
    assert model.domain == "kari.mayim-mayim.com"
    assert model.track_status == "active_verified"
    assert model.is_active_verified_track is True

def test_verified_domain_track_summary_parsing():
    read_model_data = {
        "domain": "kari.example.com",
        "sponsor_type": "verified_domain_track",
        "track_type": "verified_domain_track",
        "track_plan": "verified_domain_track_lite",
        "track_status": "active_verified",
        "duration_days": 30,
        "observation_interval_hours": 168,
        "observation_profile": "public_safe_light",
        "verification_required": True,
        "domain_owner_verified": False,
        "sponsor_verified": True,
        "domain_control_verified": True,
        "sponsor_verification_status": "verified",
        "verification_scope": "domain_control_not_legal_ownership",
        "not_legal_ownership_proof": True,
        "is_active_verified_track": True,
        "not_a_verdict": True,
        "not_a_security_scan": True,
        "not_an_endorsement": True,
        "not_a_certification": True,
        "not_a_recommendation": True,
        "not_a_trust_score": True
    }
    mock_data = {
        "domain": "kari.example.com",
        "current_track": read_model_data,
        "sponsor_verified": True,
        "domain_control_verified": True,
        "not_legal_ownership_proof": True,
        "not_a_trust_score": True,
        "has_active_verified_domain_track": True
    }
    summary = VerifiedDomainTrackSummary(**mock_data)
    assert summary.has_active_verified_domain_track is True
    assert summary.current_track.track_plan == "verified_domain_track_lite"

@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=True)
@patch("ln_church_agent.client.Payment402Client.execute_detailed")
def test_client_register_verified_domain_track(mock_exec, mock_validate):
    client = LnChurchClient(private_key=STABLE_PRIVATE_KEY)
    
    mock_res = MagicMock()
    mock_res.response = {
        "request_id": "obsreq_vdt_123",
        "domain": "kari.example.com",
        "status": "pending_verification",
        "requester_paid": True,
        "sponsor_type": "verified_domain_track",
        "track_type": "verified_domain_track",
        "track_plan": "verified_domain_track_lite",
        "track_status": "pending_verification",
        "duration_days": 30,
        "observation_interval_hours": 168,
        "observation_profile": "public_safe_light",
        "verification_required": True,
        "domain_owner_verified": False,
        "sponsor_verified": False,
        "domain_control_verified": False,
        "sponsor_verification_status": "unverified",
        "verification_scope": "domain_control_not_legal_ownership"
    }
    mock_res.response_headers = {
        "X-LN-Result-Handle": "paidres_123",
        "X-LN-Request-Hash": "hash123"
    }
    mock_exec.return_value = mock_res

    res = client.register_verified_domain_track("kari.example.com")

    assert res.request_id == "obsreq_vdt_123"
    assert res.result_handle == "paidres_123"
    assert res.request_hash == "hash123"
    
    mock_exec.assert_called_once()
    args, kwargs = mock_exec.call_args
    assert args[1] == "https://kari.mayim-mayim.com/api/bazaar/verified-domain-tracks"
    assert kwargs["payload"]["domain"] == "kari.example.com"
    assert kwargs["payload"]["agentId"] == client.agent_id

@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=True)
@patch("ln_church_agent.client.Payment402Client.execute_detailed")
def test_client_register_verified_domain_track_with_base_url(mock_exec, mock_validate):
    client = LnChurchClient(private_key=STABLE_PRIVATE_KEY)
    mock_res = MagicMock()
    mock_res.response = {"request_id": "obsreq_123", "domain": "kari.example.com", "status": "pending"}
    mock_res.response_headers = {}
    mock_exec.return_value = mock_res

    # [品質改善] base_url 指定時にエンドポイントパスが正しく合成される仕様の検証
    client.register_verified_domain_track("kari.example.com", base_url="https://kari.mayim-mayim.com/")
    args, kwargs = mock_exec.call_args
    assert args[1] == "https://kari.mayim-mayim.com/api/bazaar/verified-domain-tracks"

@patch("ln_church_agent.client.Payment402Client.execute_detailed")
def test_invalid_plan_id_rejected_before_execution(mock_exec):
    policy = PaymentPolicy(max_spend_per_tx_usd=25.0, max_spend_per_session_usd=100.0)
    client = LnChurchClient(private_key=STABLE_PRIVATE_KEY, policy=policy)
    
    with pytest.raises(ValueError, match="Unsupported Verified Domain Track plan"):
        client.register_verified_domain_track("kari.example.com", plan_id="invalid_plan")
    
    mock_exec.assert_not_called()

@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=False)
@patch("ln_church_agent.client.Payment402Client.execute_detailed")
def test_invalid_domain_rejected_before_execution(mock_exec, mock_validate):
    client = LnChurchClient(private_key=STABLE_PRIVATE_KEY)
    with pytest.raises(ValueError, match="Invalid public domain"):
        client.register_verified_domain_track("invalid_domain^^")
    
    mock_exec.assert_not_called()

# [品質改善] MagicMock による誤魔化しを排除し、実モデル Pydantic パース構造の厳格な検証
@patch("ln_church_agent.client.LnChurchClient.get_domain_observation_read_model")
def test_client_get_domain_verified_track(mock_get_read_model):
    client = LnChurchClient(private_key=STABLE_PRIVATE_KEY)
    
    mock_get_read_model.return_value = DomainObservationDomainReadModel(
        domain="kari.example.com",
        verified_domain_track={
            "has_active_verified_domain_track": True,
            "current_track": {
                "track_type": "verified_domain_track",
                "track_plan": "verified_domain_track_lite",
                "track_status": "active_verified",
                "is_active_verified_track": True,
                "request_id": "obsreq_123",
                "domain": "kari.example.com",
                "observation_count": 1,
                "sponsor_verification_status": "verified",
                "domain_control_verified": True,
                "sponsor_verified": True,
                "domain_owner_verified": True,
                "verification_scope": "domain_control_not_legal_ownership",
                "not_legal_ownership_proof": True,
                "not_a_verdict": True,
                "not_a_security_scan": True,
                "not_an_endorsement": True,
                "not_a_certification": True,
                "not_a_recommendation": True,
                "not_a_trust_score": True
            },
            "not_a_verdict": True,
            "not_a_recommendation": True,
            "not_a_trust_score": True
        }
    )

    res = client.get_domain_verified_track("kari.example.com")

    assert res is not None
    assert res.has_active_verified_domain_track is True
    assert res.current_track.domain == "kari.example.com"
    assert res.current_track.track_plan == "verified_domain_track_lite"
    mock_get_read_model.assert_called_once_with("kari.example.com")

# [品質改善] CLIリークテスト（JSONへのsecret漏洩チェック）
@patch("sys.stdout", new_callable=io.StringIO)
@patch("ln_church_agent.client.Payment402Client.execute_detailed")
@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=True)
def test_cli_register_track_json_does_not_leak_secrets(mock_val, mock_exec, mock_stdout):
    mock_res = MagicMock()
    mock_res.response = {
        "request_id": "obsreq_vdt_1",
        "domain": "kari.example.com",
        "status": "pending_verification",
        "track_plan": "verified_domain_track_lite",
        "observation_interval_hours": 168,
        "verification_required": True,
        "requester_paid": True,
        "sponsor_type": "verified_domain_track",
        "track_type": "verified_domain_track",
        "track_status": "pending_verification",
        "duration_days": 30,
        "observation_profile": "public_safe_light",
        "domain_owner_verified": False,
        "sponsor_verified": False,
        "domain_control_verified": False,
        "sponsor_verification_status": "unverified",
    }
    mock_res.response_headers = {
        "X-LN-Result-Handle": "secret_handle_123",
        "X-LN-Request-Hash": "secret_hash_456"
    }
    mock_exec.return_value = mock_res

    from ln_church_agent.cli import main
    test_args = [
        "ln-church-agent", "observe-domain", "track", "register", "kari.example.com", "--pay", "--json"
    ]
    with patch.dict("os.environ", {"AGENT_PRIVATE_KEY": STABLE_PRIVATE_KEY}):
        with patch.object(sys, 'argv', test_args):
            main()

    output = mock_stdout.getvalue()
    assert "secret_handle_123" not in output
    assert "secret_hash_456" not in output
    
    parsed = json.loads(output)
    assert parsed["domain"] == "kari.example.com"
    assert "result_handle" not in parsed

# [品質改善] --proof-file にはシークレットが保存されることの検証
@patch("ln_church_agent.client.Payment402Client.execute_detailed")
@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=True)
def test_cli_register_track_saves_proof_with_secrets(mock_val, mock_exec, tmp_path):
    mock_res = MagicMock()
    mock_res.response = {
        "request_id": "obsreq_vdt_2",
        "domain": "kari.example.com",
        "status": "pending_verification",
        "track_plan": "verified_domain_track_lite",
        "observation_interval_hours": 168,
        "verification_required": True,
        "requester_paid": True,
        "sponsor_type": "verified_domain_track",
        "track_type": "verified_domain_track",
        "track_status": "pending_verification",
        "duration_days": 30,
        "observation_profile": "public_safe_light",
        "domain_owner_verified": False,
        "sponsor_verified": False,
        "domain_control_verified": False,
        "sponsor_verification_status": "unverified",
    }
    mock_res.response_headers = {
        "X-LN-Result-Handle": "secret_handle_789",
        "X-LN-Request-Hash": "secret_hash_012"
    }
    mock_exec.return_value = mock_res

    proof_file = tmp_path / "vdt-proof.json"
    
    from ln_church_agent.cli import main
    test_args = [
        "ln-church-agent", "observe-domain", "track", "register", "kari.example.com", "--pay", "--proof-file", str(proof_file)
    ]
    with patch.dict("os.environ", {"AGENT_PRIVATE_KEY": STABLE_PRIVATE_KEY}):
        with patch.object(sys, 'argv', test_args):
            main()

    assert proof_file.exists()
    parsed = json.loads(proof_file.read_text())
    assert parsed["result_handle"] == "secret_handle_789"
    assert parsed["request_hash"] == "secret_hash_012"

# [受入条件の追加] sponsor challenge / verify ワークフローの --proof-file 受入テスト
@patch("ln_church_agent.client.LnChurchClient.create_domain_sponsor_challenge")
def test_cli_sponsor_challenge_loads_proof_file(mock_challenge, tmp_path):
    proof_file = tmp_path / "vdt-proof.json"
    proof_data = {
        "schema_version": "ln_church.verified_domain_track_proof.v1",
        "request_id": "obsreq_123",
        "domain": "kari.example.com",
        "track_plan": "verified_domain_track_lite",
        "result_handle": "proof_handle_abc",
        "request_hash": "proof_hash_def"
    }
    proof_file.write_text(json.dumps(proof_data))

    from ln_church_agent.cli import main
    test_args = [
        "ln-church-agent", "observe-domain", "sponsor", "challenge", "obsreq_123",
        "--proof-file", str(proof_file), "--output-file", str(tmp_path / "challenge.json")
    ]
    with patch.object(sys, 'argv', test_args):
        main()

    # proof-file から引数が正しく client メソッドへ引き渡されていることの検証
    mock_challenge.assert_called_once()
    kwargs = mock_challenge.call_args[1]
    assert kwargs["result_handle"] == "proof_handle_abc"
    assert kwargs["request_hash"] == "proof_hash_def"

@patch("ln_church_agent.client.LnChurchClient.verify_domain_sponsor")
def test_cli_sponsor_verify_explicit_arguments_precede_proof_file(mock_verify, tmp_path):
    proof_file = tmp_path / "vdt-proof.json"
    proof_data = {
        "schema_version": "ln_church.verified_domain_track_proof.v1",
        "request_id": "obsreq_123",
        "domain": "kari.example.com",
        "track_plan": "verified_domain_track_lite",
        "result_handle": "proof_handle_abc",
        "request_hash": "proof_hash_def"
    }
    proof_file.write_text(json.dumps(proof_data))

    from ln_church_agent.cli import main
    # [受入要件] 明示的な引数（--result-handle等）が --proof-file より優先されることの検証
    test_args = [
        "ln-church-agent", "observe-domain", "sponsor", "verify", "obsreq_123",
        "--proof-file", str(proof_file),
        "--result-handle", "explicit_handle_xyz",
        "--request-hash", "explicit_hash_xyz"
    ]
    with patch.object(sys, 'argv', test_args):
        main()

    mock_verify.assert_called_once()
    kwargs = mock_verify.call_args[1]
    assert kwargs["result_handle"] == "explicit_handle_xyz"
    assert kwargs["request_hash"] == "explicit_hash_xyz"

@patch("ln_church_agent.client.LnChurchClient.verify_domain_sponsor")
def test_cli_sponsor_verify_proof_file_only(mock_verify, tmp_path):
    """Ensure sponsor verify works perfectly when pulling credentials strictly from the proof file."""
    proof_file = tmp_path / "vdt-proof.json"
    proof_data = {
        "schema_version": "ln_church.verified_domain_track_proof.v1",
        "request_id": "obsreq_123",
        "domain": "kari.example.com",
        "track_plan": "verified_domain_track_lite",
        "result_handle": "proof_handle_only_abc",
        "request_hash": "proof_hash_only_def"
    }
    proof_file.write_text(json.dumps(proof_data))

    from ln_church_agent.cli import main
    # [受入要件] 明示引数なし、--proof-file のみの指定ケース
    test_args = [
        "ln-church-agent", "observe-domain", "sponsor", "verify", "obsreq_123",
        "--proof-file", str(proof_file)
    ]
    with patch.object(sys, 'argv', test_args):
        main()

    # ファイル内の値がそのまま渡されていることを厳格に検証
    mock_verify.assert_called_once()
    kwargs = mock_verify.call_args[1]
    assert kwargs["result_handle"] == "proof_handle_only_abc"
    assert kwargs["request_hash"] == "proof_hash_only_def"

@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=True)
@patch("ln_church_agent.client.Payment402Client.execute_detailed")
def test_client_register_verified_domain_track_with_monzen_base_url(mock_exec, mock_validate):
    """
    Ensure that even if self.base_url contains the /api/agent/monzen path,
    the bazaar endpoint is correctly constructed using only the origin (scheme + netloc).
    """
    # Monzen ゾーンのパスが含まれるベースURLでクライアントを初期化
    client = LnChurchClient(
        private_key=STABLE_PRIVATE_KEY, 
        base_url="https://kari.mayim-mayim.com/api/agent/monzen"
    )
    
    mock_res = MagicMock()
    mock_res.response = {"request_id": "obsreq_123", "domain": "kari.example.com", "status": "pending"}
    mock_res.response_headers = {}
    mock_exec.return_value = mock_res

    # 実行
    client.register_verified_domain_track("kari.example.com")
    
    # execute_detailed に渡されるURLが、絶対URLであり、かつ /api/agent/monzen が混入していないことを検証
    args, kwargs = mock_exec.call_args
    assert args[1] == "https://kari.mayim-mayim.com/api/bazaar/verified-domain-tracks"


@patch("ln_church_agent.client.validate_public_domain_for_observation", return_value=True)
@patch("requests.request")  # 最下層のHTTP通信を直接モック
def test_client_register_verified_domain_track_sends_correct_absolute_url(mock_request, mock_validate):
    """
    execute_detailed をモックせず、requests.request を直接モックすることで、
    Monzenパスが混入した環境下でも最下層で正しいBazaar絶対URLへ射出されるかを厳格に検証する。
    """
    # 意図的に Monzen パスを含む状態の base_url を持つクライアントを生成
    client = LnChurchClient(
        private_key=STABLE_PRIVATE_KEY,
        base_url="https://kari.mayim-mayim.com/api/agent/monzen"
    )
    
    # 402/200のダミーレスポンスを設定 (実際の通信構造に合わせて最小限のモック表現)
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {
        "request_id": "obsreq_vdt_123",
        "domain": "kari.example.com",
        "status": "pending_verification",
        "track_plan": "verified_domain_track_lite"
    }
    mock_res.headers = {
        "X-LN-Result-Handle": "paidres_123",
        "X-LN-Request-Hash": "hash123"
    }
    mock_request.return_value = mock_res

    # 実行
    res = client.register_verified_domain_track("kari.example.com")

    # [検証要件] requests.request が呼び出された際の第2引数（URL）が完全に一致すること
    mock_request.assert_called_once()
    called_args, called_kwargs = mock_request.call_args
    
    # requests.request(method, url, ...) の形を前提に検証
    actual_url = called_args[1] if len(called_args) > 1 else called_kwargs.get("url")
    assert actual_url == "https://kari.mayim-mayim.com/api/bazaar/verified-domain-tracks"