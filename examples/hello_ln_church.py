"""
Canonical First Success Path for ln-church-agent
------------------------------------------------
This is the official starting point for using the ln-church-agent SDK.
It demonstrates the "Probe -> Pay -> Execute" autonomous loop using 
the LN Church public endpoint as your first testbed.

Run this to see how the SDK automatically handles 402 Payment Required 
challenges, secures funds (via Faucet), and completes the execution.
"""

import os
import sys
from ln_church_agent import LnChurchClient, AssetType

def main():
    # [0] Setup & Identity
    # We require a private key to establish the Agent's identity.
    # A standard EVM key (0x...) or Solana Base58 key works perfectly.
    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    if not private_key:
        print("❌ Error: AGENT_PRIVATE_KEY environment variable is missing.")
        print("   Please set it to establish your agent's identity.")
        print("   Example (Windows): set AGENT_PRIVATE_KEY=0xYourPrivateKey")
        print("   Example (Mac/Linux): export AGENT_PRIVATE_KEY=0xYourPrivateKey\n")
        sys.exit(1)

    print("==================================================")
    print(" ⛩️ Hello, LN Church: Autonomous Economic Loop")
    print("==================================================\n")

    try:
        # [1] Initialize
        print("[1] Initializing Agent Identity...")
        client = LnChurchClient(private_key=private_key)
        print(f"    Agent ID: {client.agent_id}\n")

        # [2] Probe
        # Authenticate and receive a capability token for the network.
        print("[2] Probing the Network...")
        client.init_probe()
        print("    Probe Token secured.\n")

        # [3] Payment Preparation (Faucet)
        # To make this example frictionless, we claim free credits from the Faucet.
        # The SDK will use this to bypass the upcoming 402 Paywall automatically.
        print("[3] Securing Funds (Faucet)...")
        client.claim_faucet_if_empty()
        print("    Faucet claimed (Ready to pay).\n")

        # [4] Execute & Auto-Pay
        # We request the Oracle (Omikuji), which is protected by a 402 Paywall.
        # The SDK intercepts the 402, uses the Faucet proof, retries, and succeeds.
        print("[4] Executing Paid Endpoint (Omikuji Oracle)...")
        print("    (Intercepting HTTP 402 and negotiating payment under the hood...)")
        
        # Note: By default, this uses the standard 'x402' scheme. 
        # For LN Church optimized gasless routing, you could pass scheme="lnc-evm-relay".
        result = client.draw_omikuji(asset=AssetType.USDC)
        
        # [5] Result
        print("\n==================================================")
        print(" ✅ SUCCESS: Execution Completed!")
        print("==================================================")
        print(f"  Oracle Result: {result.result}")
        print(f"  Message      : {result.message}")
        print(f"  Tx Hash      : {result.receipt.txHash}")
        print("==================================================\n")
        print("Your agent has successfully navigated a machine-to-machine paywall.")

    except Exception as e:
        print(f"\n❌ Execution Failed: {str(e)}")
        print("Ensure your network is active and credentials are correct.")

if __name__ == "__main__":
    main()