# sandbox_harness_verification.py

import os
import sys
from pprint import pprint
from ln_church_agent import LnChurchClient

def main():
    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    if not private_key:
        print("❌ Error: AGENT_PRIVATE_KEY environment variable is missing.")
        sys.exit(1)

    # ★ 追加: LNBits (または Alby) の環境変数を取得
    ln_url = os.environ.get("LNBITS_URL", "https://legend.lnbits.com")
    ln_key = os.environ.get("LNBITS_ADMIN_KEY")
    
    if not ln_key:
        print("❌ Error: LNBITS_ADMIN_KEY environment variable is missing.")
        print("   A valid Lightning wallet is required to execute the L402 sandbox run.")
        sys.exit(1)

    print("==================================================")
    print(" 🧪 LN Church Sandbox Harness Integration Test")
    print("==================================================\n")

    #  ln_adapter を構築するために必要な情報を渡す
    client = LnChurchClient(
        private_key=private_key,
        ln_provider="lnbits",
        ln_api_url=ln_url,
        ln_api_key=ln_key
    )

    try:
        print("[1] Executing Native L402 Harness Run (402 -> Pay -> 200 -> Report)...")
        result = client.run_l402_sandbox_harness()

        print("\n==================================================")
        if result.ok:
            print(" ✅ SUCCESS: Harness Run Completed & Matched!")
        else:
            print(" ❌ WARNING: Harness Run Finished with Mismatch or Error!")
        print("==================================================")

        print(f"  Target URL       : {result.target_url}")
        print(f"  Run ID           : {result.run_id}")
        print(f"  Executor Mode    : {result.executor_mode}")
        print(f"  Payment Performed: {result.payment_performed}")
        print(f"  Hash Matched     : {result.canonical_hash_matched}")
        print(f"  Report Accepted  : {result.report_accepted} (HTTP {result.report_status_code})")
        print("\n  -- Raw Report Response --")
        pprint(result.raw_report_response)
        print("==================================================\n")

    except Exception as e:
        print(f"\n💥 Execution Failed: {str(e)}")

if __name__ == "__main__":
    main()