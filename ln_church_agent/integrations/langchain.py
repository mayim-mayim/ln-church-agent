from typing import Optional, Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field
from ..client import LnChurchClient
from ..models import AssetType

class OmikujiInput(BaseModel):
    query: str = Field(description="The user's question or context for the oracle.")

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
            result = self.client.draw_omikuji(asset=self.preferred_asset)
            return (
                f"【オラクルからの神託】\n"
                f"位階: {result.result}\n"
                f"メッセージ: {result.message}\n"
                f"(決済完了証明: {result.receipt.txHash})"
            )
        except Exception as e:
            return f"神託の取得に失敗しました: {str(e)}"