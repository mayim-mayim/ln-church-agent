"""
Sandbox Harness Phase B: Delegated Path Verification
----------------------------------------------------
Delegated Path (外部エグゼキュータへの委譲) を使って Sandbox 突破を検証します。
オプションで意図的な Hash Mismatch を発生させてレポートを送信できます。
"""
import os
import sys
import argparse
from pprint import pprint
from ln_church_agent import LnChurchClient
from ln_church_agent.adapters.l402_delegate import LightningLabsL402Executor
from ln_church_agent.crypto.lightning import LegacyLNAdapter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mismatch", action="store_true", help="意図的に誤ったハッシュを報告する")
    args = parser.parse_args()

    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    ln_url = os.environ.get("LNBITS_URL", "https://legend.lnbits.com")
    ln_key = os.environ.get("LNBITS_ADMIN_KEY")

    if not private_key or not ln_key:
        print("❌ Error: AGENT_PRIVATE_KEY and LNBITS_ADMIN_KEY are required.")
        sys.exit(1)

    print("==================================================")
    print(" 🧪 Phase B: Delegated Executor Integration Test")
    if args.mismatch:
        print(" ⚠️  MODE: Intentional Mismatch Simulation")
    print("==================================================\n")

    # [1] アダプターの準備
    ln_adapter = LegacyLNAdapter(api_url=ln_url, api_key=ln_key, provider="lnbits")

    # [2] Lightning Labs Executor (シミュレーター) の初期化
    ll_executor = LightningLabsL402Executor(ln_adapter=ln_adapter)

    # [3] Clientの初期化 (委譲をONにし、Sandboxホストを許可)
    client = LnChurchClient(
        private_key=private_key,
        ln_adapter=ln_adapter,
        l402_executor=ll_executor,
        prefer_lightninglabs_l402=True,
        l402_delegate_allowed_hosts=["kari.mayim-mayim.com"]
    )

    try:
        print(f"[Run] Executing via '{ll_executor.__class__.__name__}'...")
        
        if args.mismatch:
            # === Mismatch シミュレーション ===
            exec_result = client.execute_detailed("GET", "/api/agent/sandbox/l402/basic")
            resp = exec_result.response
            meta = resp.get("meta", {})
            
            # わざと間違ったハッシュを捏造
            bad_hash = "mismatch_simulated_hash_99999"
            receipt = exec_result.settlement_receipt
            
            report_payload = {
                "run_id": meta.get("run_id", ""),
                "scenario_id": meta.get("scenario_id", ""),
                "canonical_hash_expected": meta.get("canonical_hash_expected", ""),
                "canonical_hash_observed": bad_hash, 
                "executor_mode": "lightninglabs-delegated",
                "delegate_source": "lightninglabs-delegated",
                "cached_token_used": receipt.cached_token_used if receipt else False,
                "payment_performed": receipt.payment_performed if receipt else True,
                "fee_sats": receipt.fee_sats if receipt else 0,
                "sdk_version": "1.5.11",
                "interop_token": meta.get("interop_token", ""),
                "comparison_class": "validation_test",
                "test_mode": "intentional_mismatch"
            }
            
            print("  -> Simulating hash mismatch for Interop Matrix verification...")
            report_exec = client.execute_detailed("POST", "/api/agent/sandbox/interop/report", payload=report_payload)
            
            print("\n==================================================")
            print(" ⚠️ Result: lightninglabs-delegated - Intentional Mismatch Sent!")
            print(f"  Run ID           : {meta.get('run_id', '')}")
            print(f"  Report Accepted  : {report_exec.response.get('status') == 'success'}")
            print("==================================================\n")

        else:
            # === 通常の Happy Path 実行 ===
            result = client.run_l402_sandbox_harness()

            print("\n==================================================")
            print(f" ✅ Result: {result.executor_mode} - OK: {result.ok}")
            print(f"  Run ID           : {result.run_id}")
            print(f"  Delegate Source  : {result.delegate_source}")
            print(f"  Token Cached     : {result.cached_token_used}")
            print(f"  Hash Matched     : {result.canonical_hash_matched}")
            print("==================================================\n")

    except Exception as e:
        print(f"\n💥 Execution Failed: {str(e)}")

if __name__ == "__main__":
    main()