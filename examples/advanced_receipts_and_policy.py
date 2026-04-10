"""
Advanced Execution Path (v1.2.0)
--------------------------------
Demonstrates the use of strict PaymentPolicies, the NWC Adapter (via Bridge),
and leveraging SettlementReceipts for agentic decision-making.
"""
import os
from ln_church_agent import Payment402Client, PaymentPolicy
from ln_church_agent.adapters.nwc import NWCAdapter

def main():
    print("🛡️ Initializing Agent with Strict Policies & Remote NWC Wallet...")

    # 1. Define strict policy (e.g., Only allow L402, max 1.0 USD)
    strict_policy = PaymentPolicy(
        allowed_schemes=["L402"],
        allowed_assets=["SATS"],
        max_spend_per_tx_usd=1.0 
    )

    # 2. Setup NWC Adapter (Agent holds NO private keys)
    nwc_uri = os.environ.get("NWC_URI", "nostr+walletconnect://mock...")
    nwc_bridge = os.environ.get("NWC_BRIDGE_URL", "https://your-nwc-bridge.com/api/nwc")
    nwc_adapter = NWCAdapter(nwc_uri=nwc_uri, bridge_url=nwc_bridge)

    # 3. Initialize Client
    client = Payment402Client(
        base_url="https://kari.mayim-mayim.com",
        ln_adapter=nwc_adapter,
        policy=strict_policy
    )

    try:
        # 4. Execute 402 endpoint
        print("⚡ Executing paid action...")
        result = client.execute_request("POST", "/api/agent/omikuji", payload={"asset": "SATS"})
        
        # 5. Leverage the Settlement Receipt
        receipt = client.last_receipt
        print("\n✅ Execution Successful!")
        print("--- Agent Settlement Receipt ---")
        print(f"Receipt ID : {receipt.receipt_id}")
        print(f"Network    : {receipt.network} ({receipt.scheme})")
        print(f"Amount     : {receipt.settled_amount} {receipt.asset}")
        print(f"Status     : {receipt.verification_status}")
        print(f"Proof      : {receipt.proof_reference[:15]}...")
        print("--------------------------------")

    except Exception as e:
        print(f"❌ Blocked or Failed: {e}")

if __name__ == "__main__":
    main()