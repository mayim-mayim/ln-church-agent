from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class AssetType(str, Enum):
    JPYC = "JPYC"
    USDC = "USDC"
    SATS = "SATS"
    FAUCET_CREDIT = "FAUCET_CREDIT"

class SchemeType(str, Enum):
    x402 = "x402"
    x402_direct = "x402-direct"
    L402 = "L402"
    MPP = "MPP"

class PaymentAuth(BaseModel):
    scheme: SchemeType
    proof: str

class OmikujiReceipt(BaseModel):
    txHash: str
    ritual: str
    timestamp: int
    paid: str
    agentId: str
    verify_token: str
    probe_verified: Optional[bool] = False
    proof_class: Optional[str] = None

class OmikujiResponse(BaseModel):
    status: str
    result: str
    message: str
    tx_ref: str
    receipt: OmikujiReceipt
    paid: str

class AgentIdentity(BaseModel):
    status: str
    public_profile_url: str
    # その他パスポート情報