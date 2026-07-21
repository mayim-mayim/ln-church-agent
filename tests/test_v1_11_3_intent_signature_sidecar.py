import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient
from ln_church_agent.integrations.mcp_inspect import build_mcp_observation_payload

def _get_client():
    return LnChurchClient(private_key="0x" + "1" * 64)

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_a_sync_submit_accepts_intent_sidecars(mock_exec):
    """Test A: Sync submit accepts step-level intent_signature and classification_claims"""
    client = _get_client()
    mock_exec.return_value = {"status": "accepted"}

    goal = {"goal_text": "Lookup company profile", "intent_signature": {"target_object": "company"}}
    attempt = {"attempt_mode": "free"}
    steps = [{
        "step_index": 1,
        "step_role": "fetch",
        "surface_type": "paid_surface",
        "intent_signature": {
            "schema_version": "ln_church.intent_signature.v0",
            "operation_verb": "lookup",
            "target_object": "company",
            "input_shape": ["company_name", "domain_optional"],
            "expected_output_shape": ["profile", "summary"],
            "execution_mode": "read_only"
        },
        "classification_claims": [{
            "namespace": "ln_church.agent_intent.experimental",
            "taxonomy_version": "agent_intent_taxonomy.v0",
            "category_id": "company_profile_lookup",
            "source": "agent_inferred",
            "confidence": 0.72,
            "confidence_method": "agent_self_estimated",
            "status": "candidate",
            "classification_basis": ["agent_goal", "endpoint_description", "response_shape"],
            "not_a_recommendation": True,
            "not_a_verdict": True
        }]
    }]

    client.submit_goal_attempt_observation(
        goal=goal, attempt=attempt, steps=steps,
        intent_sidecar_metadata={
            "schema_version": "ln_church.intent_sidecar_metadata.v0",
            "sidecar_kind": "experimental_intent_signature_observation",
            "not_a_recommendation": True,
            "not_a_verdict": True
        }
    )

    payload = mock_exec.call_args.kwargs["payload"]
    assert mock_exec.call_args.args[1] == "/api/agent/external/attempt/observe"
    assert payload["schema_version"] == "goal_attempt.v1"
    assert "intent_sidecar_metadata" in payload

    step0 = payload["steps"][0]
    assert "intent_signature" in step0
    assert step0["intent_signature"]["operation_verb"] == "lookup"
    assert "classification_claims" in step0
    assert step0["classification_claims"][0]["not_a_recommendation"] is True
    assert step0["classification_claims"][0]["not_a_verdict"] is True

@patch("ln_church_agent.client.LnChurchClient.execute_request_async")
def test_b_async_submit_accepts_sidecars(mock_exec_async):
    """Test B: Async submit accepts sidecars and outcome remains optional"""
    client = _get_client()
    mock_exec_async.return_value = {"status": "accepted"}

    async def run():
        await client.submit_goal_attempt_observation_async(
            goal={"goal_text": "test"},
            attempt={"attempt_mode": "free"},
            steps=[{"intent_signature": {"target_object": "data"}}]
        )
    asyncio.run(run())

    payload = mock_exec_async.call_args.kwargs["payload"]
    assert "intent_signature" in payload["steps"][0]
    assert "outcome" not in payload

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_c_legacy_payload_remains_compatible(mock_exec):
    """Test C: Legacy payload remains compatible (no intent signatures required)"""
    client = _get_client()
    client.submit_goal_attempt_observation(
        goal={"goal_text": "Legacy test"}, attempt={"attempt_mode": "free"}, steps=[{"step_index": 1}]
    )
    payload = mock_exec.call_args.kwargs["payload"]
    assert "intent_signature" not in payload["steps"][0]
    assert payload["schema_version"] == "goal_attempt.v1"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_d_and_e_secret_stripping_applies_recursively(mock_exec):
    """Test D & E: Secret stripping applies recursively and shapes don't leak secrets"""
    client = _get_client()

    unsafe_steps = [{
        "surface_type": "paid_surface",
        "payment_performed": True,
        "intent_signature": {
            "target_object": "company",
            "input_shape": ["company_name"],
            "headers": {"Authorization": "Bearer SECRET"},
            "api_key": "SECRET_API_KEY"
        },
        "classification_claims": [{
            "category_id": "company_profile_lookup",
            "proof": "SECRET_PROOF",
            "private_key": "SECRET_KEY"
        }]
    }]

    client.submit_goal_attempt_observation(
        goal={"goal_text": "test"}, attempt={}, steps=unsafe_steps
    )

    step0 = mock_exec.call_args.kwargs["payload"]["steps"][0]

    assert step0["payment_performed"] is True
    assert step0["intent_signature"]["target_object"] == "company"
    assert step0["classification_claims"][0]["category_id"] == "company_profile_lookup"

    assert "headers" not in step0["intent_signature"]
    assert "api_key" not in step0["intent_signature"]
    assert "proof" not in step0["classification_claims"][0]
    assert "private_key" not in step0["classification_claims"][0]

@patch("requests.request")
def test_f_no_automatic_telemetry_hook(mock_req):
    """Test F: No automatic telemetry hook in standard execution paths"""
    client = LnChurchClient(base_url="https://api.test", private_key="0x" + "1"*64)
    mock_res = MagicMock(status_code=200, content=b'{"status":"success"}')
    mock_res.json.return_value = {"status": "success"}
    mock_req.return_value = mock_res

    client.execute_request("POST", "/api/v1/resource", payload={"test": "data"})
    assert mock_req.call_count == 1
    assert "observe" not in mock_req.call_args.args[1]

def test_g_mcp_observation_payload_remains_unchanged():
    """Test G: MCP observation payload must strictly exclude all intent sidecars"""
    # 💡 GPT指摘反映: Forbiddenなキーをすべて含んだフェイク入力を用意
    fake_res = {
        "url": "http://public.example",
        "method": "GET",
        "status_code": 402,
        "settlement_rails_detected": ["L402"],
        "intent_signature": {"target_object": "test"},
        "classification_claims": [{"category_id": "company_profile_lookup"}],
        "intent_sidecar_metadata": {"schema_version": "ln_church.intent_sidecar_metadata.v0"},
        "category_id": "company_profile_lookup",
        "taxonomy_version": "agent_intent_taxonomy.v0"
    }

    payload = build_mcp_observation_payload(fake_res)

    forbidden = {
        "intent_signature",
        "classification_claims",
        "intent_sidecar_metadata",
        "candidate_intent_groups",
        "category_id",
        "taxonomy_version"
    }

    # Payload内のどこにも混ざっていないことを確認
    assert forbidden.isdisjoint(payload.keys())
    assert forbidden.isdisjoint(payload.get("protocol", {}).keys())
    assert forbidden.isdisjoint(payload.get("evidence", {}).keys())

def test_h_no_payment_behavior_changed():
    """Test H: Structural confirmation that core models haven't mutated execution rules"""
    from ln_church_agent.capabilities import get_capability_matrix
    matrix = get_capability_matrix()
    l402 = next((r for r in matrix if r["id"] == "l402"), None)
    assert l402["execution_behavior"] == "execute"
    assert l402["proof_semantics"] == "verified"

def test_i_intent_signature_is_secret_stripped_but_not_entity_validated():
    """Test I: Explicitly document that shape-only is currently caller responsibility."""
    client = _get_client()
    clean = client._strip_secrets_from_evidence({
        "intent_signature": {
            "target_object": "OpenAI",
            "input_shape": ["株式会社Xの非公開調査をしてください"],
            "api_key": "SECRET"
        }
    })

    # Entity values are NOT validated/stripped by the current SDK layer
    assert clean["intent_signature"]["target_object"] == "OpenAI"
    assert clean["intent_signature"]["input_shape"] == ["株式会社Xの非公開調査をしてください"]
    # But secrets ARE strictly stripped
    assert "api_key" not in clean["intent_signature"]
