from typing import Optional, Type, List
try:
    from langchain_core.tools import BaseTool
except ImportError:
    raise ImportError("Install with `pip install ln-church-agent[langchain]`")
from pydantic import BaseModel, Field
from ..client import LnChurchClient
from ..models import AssetType

# --- 共有クライアントの初期化ヘルパー ---
def _get_ready_client(private_key: str) -> LnChurchClient:
    client = LnChurchClient(private_key=private_key, auto_navigate=True)
    client.init_probe()
    client.claim_faucet_if_empty()
    return client

# ==========================================
# Tool Schemas
# ==========================================
class OmikujiInput(BaseModel):
    query: str = Field(description="Context for the oracle.")

class ConfessionInput(BaseModel):
    raw_message: str = Field(description="The error log, stack trace, or failure context to report.")

class CompareInput(BaseModel):
    trial_id: str = Field(default="INITIATION1", description="The trial ID to compare.")

# ==========================================
# Tools
# ==========================================
class LNChurchOracleTool(BaseTool):
    name: str = "ln_church_oracle"
    description: str = (
        "Use this tool when you need an unbiased pseudo-random seed, a fortune (Omikuji), "
        "or to mathematically prove your Wallet capability. "
        "Behind the scenes, this tool autonomously pays via x402/L402 protocol."
    )
    args_schema: Type[BaseModel] = OmikujiInput
    client: LnChurchClient = Field(exclude=True)
    preferred_asset: AssetType = Field(default=AssetType.USDC, exclude=True)

    def _run(self, query: str) -> str:
        try:
            res = self.client.draw_omikuji(asset=self.preferred_asset)
            return f"Oracle Result: {res.result} - {res.message} (Receipt: {res.receipt.txHash})"
        except Exception as e:
            return f"Failed: {str(e)}"

class LNChurchConfessionTool(BaseTool):
    name: str = "ln_church_confession"
    description: str = "Use this to report errors, friction, or failures to the Kazuchi engine for normalization."
    args_schema: Type[BaseModel] = ConfessionInput
    client: LnChurchClient = Field(exclude=True)
    preferred_asset: AssetType = Field(default=AssetType.SATS, exclude=True)

    def _run(self, raw_message: str) -> str:
        try:
            res = self.client.submit_confession(raw_message=raw_message, asset=self.preferred_asset)
            analysis = res.recorded_schema.normalized_interpretation
            return f"Logged. Class: {analysis.failure_class}. Advice: {analysis.recommended_next_action}"
        except Exception as e:
            return f"Failed: {str(e)}"

class LNChurchCompareTool(BaseTool):
    name: str = "ln_church_compare_benchmark"
    description: str = "Use this to compare your agent's performance against top 10 runners to find optimization bottlenecks."
    args_schema: Type[BaseModel] = CompareInput
    client: LnChurchClient = Field(exclude=True)
    preferred_asset: AssetType = Field(default=AssetType.SATS, exclude=True)

    def _run(self, trial_id: str) -> str:
        try:
            res = self.client.compare_trial_performance(trial_id=trial_id, asset=self.preferred_asset)
            return f"Bottleneck: {res.analytics.critical_bottleneck}. Advice: {res.analytics.advice}"
        except Exception as e:
            return f"神託の取得に失敗しました: {str(e)}"

# ==========================================
# Toolkit Helper
# ==========================================
def get_ln_church_tools(private_key: str, preferred_asset: AssetType = AssetType.SATS) -> List[BaseTool]:
    """LangChain Agentに一括でツールを渡すためのヘルパー関数"""
    shared_client = _get_ready_client(private_key)
    return [
        LNChurchOracleTool(client=shared_client, preferred_asset=preferred_asset),
        LNChurchConfessionTool(client=shared_client, preferred_asset=preferred_asset),
        LNChurchCompareTool(client=shared_client, preferred_asset=preferred_asset)
    ]