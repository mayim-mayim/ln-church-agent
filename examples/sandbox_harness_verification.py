# examples/sandbox_harness_verification.py

import os
import sys
from pprint import pprint
from ln_church_agent import LnChurchClient

def main():
    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    if not private_key:
        print("❌ Error: AGENT_PRIVATE_KEY environment variable is missing.")
        sys.exit(1)

    ln_url = os.environ.get("LNBITS_URL", "https://legend.lnbits.com")
    ln_key = os.environ.get("LNBITS_ADMIN_KEY")
    
    if not ln_key:
        print("❌ Error: LNBITS_ADMIN_KEY environment variable is missing.")
        sys.exit(1)

    print("==================================================")
    print(" 🧪 LN Church Sandbox Harness Integration Test")
    print("==================================================\n")

    client = LnChurchClient(
        private_key=private_key,
        ln_provider="lnbits",
        ln_api_url=ln_url,
        ln_api_key=ln_key
    )

    try:
        # --- 1. L402 Basic Sandbox ---
        print("[1] Executing Native L402 Harness Run (402 -> Pay -> 200 -> Report)...")
        res_l402 = client.run_l402_sandbox_harness()

        print(f"  Target URL       : {res_l402.target_url}")
        print(f"  Run ID           : {res_l402.run_id}")
        print(f"  Hash Matched     : {res_l402.canonical_hash_matched}")
        print(f"  Report Accepted  : {res_l402.report_accepted} (HTTP {res_l402.report_status_code})")
        if res_l402.ok:
            print(" ✅ L402 SUCCESS!\n")
        else:
            print(" ❌ L402 WARNING: Mismatch or Error!\n")

        # --- 2. MPP Charge Sandbox (新規追加) ---
        print("[2] Executing Native MPP Charge Harness Run (402 -> Pay -> 200 -> Report)...")
        res_mpp = client.run_mpp_charge_sandbox_harness()

        print(f"  Target URL       : {res_mpp.target_url}")
        print(f"  Run ID           : {res_mpp.run_id}")
        print(f"  Hash Matched     : {res_mpp.canonical_hash_matched}")
        print(f"  Report Accepted  : {res_mpp.report_accepted} (HTTP {res_mpp.report_status_code})")
        if res_mpp.ok:
            print(" ✅ MPP Charge SUCCESS!\n")
        else:
            print(" ❌ MPP Charge WARNING: Mismatch or Error!\n")

    except Exception as e:
        print(f"\n💥 Execution Failed: {str(e)}")

if __name__ == "__main__":
    main()