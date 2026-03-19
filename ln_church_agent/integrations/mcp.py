import os
from typing import Literal
from mcp.server.fastmcp import FastMCP
from ..client import Payment402Client 
from ..models import AssetType

mcp = FastMCP("HTTP_402_Payment_Client")

@mcp.tool()
def execute_paid_entropy_oracle(asset_type: Literal["USDC", "JPYC", "SATS"] = "USDC") -> str:
    """
    Autonomous execution of a paid entropy oracle via HTTP 402. 
    This tool demonstrates the agent's capability to navigate complex settlement layers (x402/L402) and Faucet fallbacks.
    Select 'SATS' for Lightning Network (L402), or 'USDC'/'JPYC' for Polygon Gasless (x402).
    """
    # 環境変数から秘密鍵を取得（なければ残高ゼロのダミーエージェントとして動く）
    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    
    print(f"[MCP] 🤖 Initializing 402 Client with asset: {asset_type}")
    client = Payment402Client(private_key=private_key)
    
    # AIが文字列で渡してきたものを、SDK内部のAssetType(Enum)に変換
    if asset_type == "SATS":
        asset_enum = AssetType.SATS
    elif asset_type == "JPYC":
        asset_enum = AssetType.JPYC
    else:
        asset_enum = AssetType.USDC

    try:
        # 1. 接続確認（Phase 0）
        client.init_probe()
        
        # 2. 残高ゼロならFaucet（Phase 0.5）
        client.claim_faucet_if_empty()
        
        # 3. 402決済突破とオラクル実行（Phase 1）
        result = client.draw_omikuji(asset=asset_enum)
        
        # AIが読みやすい形で結果を文字列として返す
        return (
            f"✅ 402 Settlement & Oracle Execution Successful!\n"
            f"Result (Rank): {result.result}\n"
            f"Oracle Message: {result.message}\n"
            f"Payment Scheme: {asset_type} (x402/L402 abstracted)\n"
            f"Cryptographic Receipt (TxHash/Preimage): {result.receipt.txHash}"
        )
        
    except Exception as e:
        return f"❌ 402 Settlement Failed: {str(e)}"

if __name__ == "__main__":
    mcp.run()