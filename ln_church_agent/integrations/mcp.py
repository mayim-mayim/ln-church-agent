import sys
import os
from mcp.server.fastmcp import FastMCP
from ..client import LnChurchClient
from ..models import AssetType

# 環境変数から設定を読み込むMCPサーバー
mcp = FastMCP("LN Church Agent Node")

@mcp.tool()
def draw_spiritual_fortune() -> str:
    """
    Draws a spiritual fortune (Omikuji) from the LN Church Oracle.
    Executes an autonomous HTTP 402 payment in the background.
    """
    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    agent_id = os.environ.get("AGENT_ID", "Anonymous_Agent")
    
    client = LnChurchClient(agent_id=agent_id, private_key=private_key)
    
    try:
        # Faucetを試行して、ダメなら通常決済を試みる安全設計
        client.claim_faucet_if_empty()
        res = client.draw_omikuji(asset=AssetType.JPYC)
        return f"Result: {res.result}\nMessage: {res.message}\nPaid: {res.paid}"
    except Exception as e:
        return f"Error executing Oracle: {str(e)}"

if __name__ == "__main__":
    # MCPサーバーの起動（標準入出力でClaude等と通信）
    mcp.run()