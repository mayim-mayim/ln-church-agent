import os
import sys
from ln_church_agent import Payment402Client, AssetType

def main():
    # Load from environment variable for identity anchor
    agent_key = os.environ.get("AGENT_PRIVATE_KEY")
    if not agent_key:
        print("⚠️ Note: AGENT_PRIVATE_KEY not set. Using anonymous pipeline simulation.")
        agent_key = "0x0000000000000000000000000000000000000000000000000000000000000001"

    print("==================================================")
    print(" ⛩️ Goal Attempt Observation & Memory API Demo")
    print("==================================================\n")

    client = Payment402Client(
        private_key=agent_key,
        base_url="https://kari.mayim-mayim.com"
    )

    # ----------------------------------------------------
    # Scenario A: Free & Unassessed Attempt
    # ----------------------------------------------------
    print("[Scenario A] Submitting a Free/Unassessed Behavior Trace...")
    try:
        res_a = client.submit_goal_attempt_observation(
            goal={
                "goal_text": "Scrape public transaction list and audit gas fluctuation patterns",
                "declared_goal_type": "data_scraping",
                "domain_hint": "crypto"
            },
            attempt={
                "attempt_mode": "free",
                "completion_status": "partial_success",
                "total_monetary_cost": 0,
                "total_reasoning_cost_estimate": "low",
                "total_latency_ms": 450
            },
            steps=[
                {
                    "step_index": 1,
                    "step_role": "fetch",
                    "surface_key": "web:explorer:gas_tracker",
                    "surface_type": "web_page",
                    "payment_performed": False,
                    "status": "success",
                    "latency_ms": 450
                }
            ],
            evidence={
                "evidence_class": "agent_report",
                "verification_status": "self_reported"
            }
        )
        print(f"  -> Server Status: {res_a.get('status')} (Attempt ID: {res_a.get('attempt_id')})")
        print("  -> Recorded successfully as 'unassessed'. Useful for retrospective graph interpretation.\n")
    except Exception as e:
        print(f"  ❌ Scenario A Failed: {e}\n")

    # ----------------------------------------------------
    # Scenario B: Mixed Paid/Free & Fully Assessed Attempt
    # ----------------------------------------------------
    print("[Scenario B] Submitting a Mixed/Assessed Economic Trace...")
    try:
        res_b = client.submit_goal_attempt_observation(
            goal={
                "goal_text": "Fetch verified risk index scores for cross-chain router contracts",
                "declared_goal_type": "security_audit",
                "domain_hint": "crypto",
                "success_criteria_text": "A confidence level over 90% achieved via premium endpoint validation"
            },
            attempt={
                "attempt_mode": "mixed",
                "completion_status": "success",
                "total_monetary_cost": 0.05,
                "total_reasoning_cost_estimate": "medium",
                "total_latency_ms": 1150
            },
            steps=[
                {
                    "step_index": 1,
                    "step_role": "fetch_free",
                    "surface_key": "web:shrine:router_list",
                    "surface_type": "web_page",
                    "payment_performed": False,
                    "status": "success",
                    "latency_ms": 350
                },
                {
                    "step_index": 2,
                    "step_role": "validate_premium",
                    "surface_key": "paid:kazuchi_audit:v1",
                    "surface_type": "paid_surface",
                    "payment_performed": True,
                    "amount": 0.05,
                    "currency": "USDC",
                    "rail": "x402",
                    "network": "eip155:137",
                    "status": "success",
                    "latency_ms": 800
                }
            ],
            outcome={
                "goal_achieved": True,
                "satisfaction_level": "full",
                "confidence": 0.94,
                "upgrade_signal": "none",
                "rubric_version": "outcome_rubric.v1"
            },
            evidence={
                "evidence_class": "execution_trace",
                "verification_status": "self_reported",
                "payment_performed": True,
                "payment_receipt_present": True
            }
        )
        print(f"  -> Server Status: {res_b.get('status')} (Attempt ID: {res_b.get('attempt_id')})")
        print("  -> Recorded successfully with full OutcomeAssessment edges.\n")
    except Exception as e:
        print(f"  ❌ Scenario B Failed: {e}\n")

    # ----------------------------------------------------
    # ⚠️ ARCHITECTURAL LAG NOTICE (Read Model Synchronization)
    # ----------------------------------------------------
    # Note: The Hon-den background exporter (Lambda_GraphToS3) compiles and 
    # updates the static S3 read models asynchronously every 5 minutes.
    #
    # Because of this 5-minute batch window, the Scenario A & B attempts you 
    # just submitted above will NOT be immediately visible in the Scenario C & D
    # read models below. This is expected behavior (eventual consistency).
    # ----------------------------------------------------

    # ----------------------------------------------------
    # Scenario C: Read Lightweight Summary (Free)
    # ----------------------------------------------------
    print("[Scenario C] Reading Free Lightweight Goal Attempt Summary Snapshot...")
    try:
        res_c = client.get_goal_attempt_summary(
            goal_type="security_audit",
            include_unassessed=True
        )
        print(f"  -> Schema Version : {res_c.get('schema_version')}")
        print(f"  -> Goals Returned : {len(res_c.get('goals', []))}")
        print(f"  -> Statement      : Not a recommendation={res_c.get('not_a_recommendation')}\n")
    except Exception as e:
        print(f"  ❌ Scenario C Failed: {e}\n")

    # ----------------------------------------------------
    # Scenario D: Read Observed Candidates (Paid - 1 SAT)
    # ----------------------------------------------------
    print("[Scenario D] Querying Paid Compact Goal Surface Candidates...")
    print("  ⚠️ Warning: This invokes an explicit HTTP 402 challenge loop if unpaid.")
    try:
        # Note: Bypasses the premium graph download overhead. Costs 1 SAT / 0.001 USDC / 1 JPYC.
        res_d = client.get_goal_surface_candidates(
            goal_type="security_audit",
            prefer_free_first=True,
            limit=5,
            asset=AssetType.SATS,
            scheme="L402"
        )
        print(f"  -> Schema Version : {res_d.get('schema_version')}")
        print(f"  -> Groups Parsed  : {len(res_d.get('candidate_groups', []))}")
        print(f"  -> Settled Status : {res_d.get('pricing', {}).get('settled')}")
        print("  -> Candidates are historical markers only, not active recipes.\n")
    except Exception as e:
        print(f"  ❌ Scenario D Failed: {e}\n")

if __name__ == "__main__":
    main()