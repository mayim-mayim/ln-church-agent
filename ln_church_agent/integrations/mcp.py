import os
from typing import Literal
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise ImportError("Install with `pip install ln-church-agent[mcp]`")
from ..client import LnChurchClient
from ..models import AssetType

mcp = FastMCP("LN_Church_Agent_Node")

def get_client() -> LnChurchClient:
    """環境変数から秘密鍵を取得し、自動ナビゲーションONのクライアントを初期化"""
    private_key = os.environ.get("AGENT_PRIVATE_KEY")
    client = LnChurchClient(private_key=private_key, auto_navigate=True)
    # 呼び出しのたびにProbeとFaucetをチェック（自動追従で必要な場合のみ実行される）
    client.init_probe()
    client.claim_faucet_if_empty()
    return client

def _to_asset_enum(asset_str: str) -> AssetType:
    return getattr(AssetType, asset_str.upper(), AssetType.USDC)

@mcp.tool()
def execute_paid_entropy_oracle(asset_type: Literal["USDC", "JPYC", "SATS"] = "USDC") -> str:
    """Execute the Omikuji oracle to get a pseudo-random seed and cryptographically prove your wallet capability."""
    try:
        client = get_client()
        result = client.draw_omikuji(asset=_to_asset_enum(asset_type))
        return f"✅ Oracle Success: Rank [{result.result}] Message: {result.message}\n(Receipt: {result.receipt.txHash})"
    except Exception as e:
        return f"❌ Oracle Failed: {str(e)}"

@mcp.tool()
def submit_agent_confession(raw_message: str, asset_type: Literal["USDC", "JPYC", "SATS"] = "SATS") -> str:
    """Submit an error log, system failure, or human-AI friction report to the Kazuchi9.3 Normalization Engine. Uses L402 by default."""
    try:
        client = get_client()
        result = client.submit_confession(raw_message=raw_message, asset=_to_asset_enum(asset_type))
        return f"✅ Confession Logged [ID: {result.confession_id}]\nAnalysis: {result.recorded_schema.normalized_interpretation.failure_class}\nNext Action: {result.recorded_schema.normalized_interpretation.recommended_next_action}"
    except Exception as e:
        return f"❌ Confession Failed: {str(e)}"

@mcp.tool()
def offer_hono_donation(amount: float, asset_type: Literal["USDC", "JPYC", "SATS"] = "SATS") -> str:
    """Make a generic donation (Hono) using the Machine Payments Protocol (MPP) or x402."""
    try:
        client = get_client()
        result = client.offer_hono(amount=amount, asset=_to_asset_enum(asset_type))
        return f"✅ Donation Accepted: {result.message}\n(Receipt: {result.receipt.txHash})"
    except Exception as e:
        return f"❌ Donation Failed: {str(e)}"

@mcp.tool()
def compare_trial_performance(trial_id: str = "INITIATION1", asset_type: Literal["USDC", "JPYC", "SATS"] = "SATS") -> str:
    """Compare your agent's performance on a specific benchmark trial against the top 10 runners to find bottlenecks."""
    try:
        client = get_client()
        result = client.compare_trial_performance(trial_id=trial_id, asset=_to_asset_enum(asset_type))
        return f"✅ Benchmark Comparison [{trial_id}]\nYour Score: {result.my_performance.score}\nTop 10 Avg Score: {result.top_10_average.score}\nBottleneck: {result.analytics.critical_bottleneck}\nAdvice: {result.analytics.advice}"
    except Exception as e:
        return f"❌ Comparison Failed: {str(e)}"

@mcp.tool()
def check_my_passport() -> str:
    """Issue or resolve your Agent Identity Passport to check your current Virtue score and Rank."""
    try:
        client = get_client()
        # パスポート発行を試行（すでに発行済みならエラーになるが無視してResolveする）
        try:
            client.issue_identity()
        except Exception:
            pass
        profile = client.resolve_identity()
        return f"🛂 Passport Identity:\nAgent ID: {profile.get('agentId')}\nRank: {profile.get('reputation', {}).get('rank')}\nVirtue Score: {profile.get('reputation', {}).get('score')}"
    except Exception as e:
        return f"❌ Identity Resolution Failed: {str(e)}"

if __name__ == "__main__":
    mcp.run()