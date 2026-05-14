from ln_church_agent.failures import build_payment_failure_record, build_payment_failure_observation_payload

# シミュレーション: feePayerがリトライごとに変わるケース
record = build_payment_failure_record(
    endpoint="https://api.example.com/x402",
    rail="x402",
    network="solana",
    asset="USDC",
    failure_class="retry_mismatch",
    failure_subclass="no_matching_payment_requirements",
    challenge_before={"feePayer": "Address_A", "amount": 100},
    challenge_after={"feePayer": "Address_B", "amount": 100},
    secondary_client_used="official-x402-python"
)

print(f"Changed Fields: {record.changed_fields}") # ['feePayer']
payload = build_payment_failure_observation_payload(record, agent_id="agent-001")
print(f"Payload ready: {payload['schema_version']}")