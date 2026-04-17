"""
External Protocol Verification
----------------------------------------------------
外部のライブ L402 エンドポイントに対して、NativeパスとDelegatedパスの
プロトコル成功率、レイテンシ、レスポンスシェイプを比較検証します。
"""
import os
import sys
import argparse
from urllib.parse import urlparse
from pprint import pprint
from ln_church_agent import LnChurchClient
from ln_church_agent.adapters.l402_delegate import LightningLabsL402Executor
from ln_church_agent.crypto.lightning import LegacyLNAdapter

def run_verification(mode: str, ln_adapter, target_url: str, debug: bool):
    print(f"\n==================================================")
    print(f" 🌐 Running Target: {mode.upper()} PATH")
    print(f" 🎯 Endpoint: {target_url}")
    print(f"==================================================")
    
    # URLから安全にドメイン(netloc)を抽出して許可リストに入れる
    target_domain = urlparse(target_url).netloc
    allowed_hosts = [target_domain]
    
    if mode == "native":
        client = LnChurchClient(ln_adapter=ln_adapter)
    else:
        ll_executor = LightningLabsL402Executor(ln_adapter=ln_adapter)
        client = LnChurchClient(
            ln_adapter=ln_adapter,
            l402_executor=ll_executor,
            prefer_lightninglabs_l402=True,
            l402_delegate_allowed_hosts=allowed_hosts
        )

    # ターゲットURLとシナリオ名を明示的に渡す
    result = client.run_external_protocol_verification(
        target_url=target_url, 
        scenario_id="external_l402_protocol_check_v1",
        debug=debug # SDKに debug フラグを渡す
    )
    
    print(f"✅ Protocol Success : {result.protocol_success}")
    if not result.ok:
        print(f"❌ Error Stage      : {result.error_stage}")
        print(f"❌ Suspected Origin : {result.suspected_failure_origin.upper()}")
        if result.upstream_host_excerpt:
            print(f"🌐 Upstream Host    : {result.upstream_host_excerpt}")
    print(f"⏱️  Latency          : {result.latency_ms} ms")
    print(f"📦 Executor Mode    : {result.executor_mode}")
    print(f"🎫 Cached Token     : {result.cached_token_used}")
    print(f"🔍 Shape Check      : {result.schema_check_reason}")
    if result.response_excerpt:
        print(f"📄 Response Excerpt : {result.response_excerpt}")
    if not result.ok:
        print(f"❌ Error Stage      : {result.error_stage}")
        print(f"❌ Error Reason     : {result.error_reason}")

def main():
    parser = argparse.ArgumentParser(description="External Protocol Verification")
    parser.add_argument("--mode", choices=["native", "delegated", "both"], default="both", help="Execution mode")
    
    parser.add_argument(
        "--target-url", 
        required=True, 
        help="Target L402 endpoint URL (e.g., https://your-api.com/data)"
    )

    parser.add_argument("--debug", action="store_true", help="詳細な決済パスログを表示")
    args = parser.parse_args()

    ln_url = os.environ.get("LNBITS_URL", "https://legend.lnbits.com")
    ln_key = os.environ.get("LNBITS_ADMIN_KEY")

    if not ln_key:
        print("❌ Error: LNBITS_ADMIN_KEY is required for live endpoint execution.")
        sys.exit(1)

    ln_adapter = LegacyLNAdapter(api_url=ln_url, api_key=ln_key, provider="lnbits")

    if args.mode in ["native", "both"]:
        run_verification("native", ln_adapter, args.target_url, args.debug) 
    
    if args.mode in ["delegated", "both"]:
        run_verification("delegated", ln_adapter, args.target_url, args.debug) 

if __name__ == "__main__":
    main()