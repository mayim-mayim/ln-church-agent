import os
import sys
from ln_church_agent import LnChurchClient, DomainObservationResultSubmission

def main():
    """
    NOTE: This is an E2E smoke test for the internal default_worker observer API.
    It DOES NOT crawl the target domain. It simply claims a target and 
    posts a synthetic, public-safe result to verify pipeline integrity.
    """
    secret = os.environ.get("LN_CHURCH_INTERNAL_SECRET")
    if not secret:
        print("❌ Error: LN_CHURCH_INTERNAL_SECRET is required to act as an observer.")
        sys.exit(1)

    print("==================================================")
    print(" 🐾 Internal Observatory Worker Observer Smoke Test")
    print("==================================================\n")

    client = LnChurchClient(agent_id="default_worker_smoke")

    print("[1] Claiming observation targets...")
    targets_res = client.claim_domain_observation_targets(observer="default_worker_smoke", limit=1, internal_secret=secret)
    
    if not targets_res.targets:
        print("ℹ️ No active targets found in the queue. Register one first.")
        sys.exit(0)
        
    target = targets_res.targets[0]
    print(f"  ✅ Claimed Target ID: {target.target_id} for domain: {target.domain}")
    
    print("\n[2] Simulating public-safe observation...")
    # Strict validation prevents non-zero payment_attempts
    submission = DomainObservationResultSubmission(
        target_id=target.target_id,
        request_id=target.request_id,
        observed_domain=target.domain,
        observed_urls=[
            {"url": f"https://{target.domain}/llms.txt", "status": 200}
        ],
        discovered_surfaces=[]
    )
    
    print("\n[3] Submitting result...")
    res = client.submit_domain_observation_result(submission, internal_secret=secret)
    
    print("✅ SUCCESS! Result recorded.")
    print(f"  Observation ID: {res.observation_id}")
    print(f"  Read Model    : {res.public_read_model_url}")

if __name__ == "__main__":
    main()