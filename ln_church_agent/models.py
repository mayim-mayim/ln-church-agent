import uuid
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

@dataclass
class ParsedChallenge:
    """
    402 Challenge 正規化モデル (Cold Spec Layer)
    各決済方式（L402, x402など）の不揃いなChallenge表現を一元化し、
    Runtimeでの分岐処理を安全かつテスト可能にする。
    """
    scheme: str
    amount: float
    asset: str
    invoice: Optional[str] = None
    macaroon: Optional[str] = None
    charge_id: Optional[str] = None
    destination: Optional[str] = None
    chain_id: Optional[int] = None
    token_address: Optional[str] = None
    relayer_endpoint: Optional[str] = None
    reference: Optional[str] = None
    raw_headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PaymentPolicy:
    """
    エージェントの自律経済行動を制限するガードレール (Policy Layer)
    v1.3.0: セッション上限とホスト制限を追加し、ハルシネーションによる資金枯渇を防止。
    """
    allowed_schemes: List[str] = field(default_factory=lambda: ["L402", "x402", "x402-direct", "x402-solana", "MPP"])
    allowed_assets: List[str] = field(default_factory=lambda: ["SATS", "USDC", "JPYC"])
    max_spend_per_tx_usd: float = 5.0 # デフォルトで1回5ドルを上限とする安全装置
    # --- v1.3.0 Additions ---
    max_spend_per_session_usd: float = 10.0
    allowed_hosts: Optional[List[str]] = None
    blocked_hosts: List[str] = field(default_factory=list)
    
    # 内部管理用セッション消費額
    _session_spent_usd: float = field(default=0.0, repr=False)

# ==========================================
# v1.4: Trust & Outcome Layer Models
# ==========================================

class ExecutionContext(BaseModel):
    """軽量な意図とセッションのコンテキスト（Workflow engineではなく、単なるタグ）"""
    intent_label: str = "default_intent"
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

class TrustDecision(BaseModel):
    """支払い前の相手先信用評価結果"""
    is_trusted: bool
    reason: str = ""

class OutcomeSummary(BaseModel):
    """決済後の期待状態（Outcome）の評価結果"""
    is_success: bool
    observed_state: str = ""
    message: str = ""

# ==========================================
# ExecutionResult
# ==========================================
class ExecutionResult(BaseModel):
    response: dict
    final_url: str
    retry_count: int = 0
    settlement_receipt: Optional[Any] = None
    used_scheme: Optional[str] = None
    used_asset: Optional[str] = None
    verification_status: Optional[str] = None
    # v1.4: 軽量なOutcome層の追加 (OutcomeSummaryもBaseModelなので安全にネスト可能)
    outcome: Optional[OutcomeSummary] = None

class SettlementReceipt(BaseModel):
    """自律エージェントが次の推論(ReAct等)に利用する最小限の決済証跡"""
    receipt_id: str = Field(default_factory=lambda: f"rec_{uuid.uuid4().hex[:12]}")
    scheme: str
    network: str
    asset: str
    settled_amount: float
    proof_reference: str
    verification_status: str = "pending" # pending, verified, self_reported

class AssetType(str, Enum):
    JPYC = "JPYC"
    USDC = "USDC"
    SATS = "SATS"
    FAUCET_CREDIT = "FAUCET_CREDIT"

class SchemeType(str, Enum):
    x402 = "x402"
    x402_direct = "x402-direct"
    x402_solana = "x402-solana"
    L402 = "L402"
    MPP = "MPP"
    PAYMENT = "Payment"

class PaymentAuth(BaseModel):
    scheme: SchemeType
    proof: str

# ==========================================
# 🧭 HATEOAS & Common Models
# ==========================================
class NextAction(BaseModel):
    instruction_for_agent: str
    method: str
    url: Optional[str] = None
    suggested_payload: Optional[Dict[str, Any]] = None
    suggested_headers: Optional[Dict[str, str]] = None

class HateoasErrorResponse(BaseModel):
    status: str
    error_code: str
    message: str
    reason: Optional[str] = None
    retryable: Optional[bool] = None
    next_action: Optional[NextAction] = None

class OmikujiReceipt(BaseModel):
    txHash: Optional[str] = None
    ritual: str
    timestamp: int
    paid: str
    AgentId: Optional[str] = None
    agentId: Optional[str] = None  # バックエンドの揺れ吸収用
    verify_token: str
    probe_verified: Optional[bool] = False
    proof_class: Optional[str] = None

class AgentIdentity(BaseModel):
    status: str
    public_profile_url: str
    agent_id: Optional[str] = None

# ==========================================
# ⛩️ Phase 1: Omikuji Models
# ==========================================
class OmikujiResponse(BaseModel):
    status: str
    result: str
    message: str
    tx_ref: str
    receipt: OmikujiReceipt
    paid: str

# ==========================================
# ⛩️ Phase 2: Confession & Hono Models
# ==========================================
class NormalizedInterpretation(BaseModel):
    failure_class: str
    constraint_class: str
    conflict_class: str
    recommended_next_action: str
    confidence: float

class FeedProjection(BaseModel):
    publishable: bool
    summary: str

class CanonicalSchema(BaseModel):
    schema_version: str
    event_summary: str
    normalized_interpretation: NormalizedInterpretation
    sanitized_evidence: List[str]
    feed_projection: FeedProjection

class ConfessionResponse(BaseModel):
    status: str
    confession_id: str
    recorded_schema: CanonicalSchema
    next_action: Optional[NextAction] = None

class HybridConfessionResponse(BaseModel):
    status: str
    oracle: str
    paid: float
    tier: str
    receiptId: str
    next_action: Optional[NextAction] = None

class HonoResponse(BaseModel):
    status: str
    message: str
    tx_ref: str
    receipt: OmikujiReceipt
    paid: str

# ==========================================
# ⛩️ Phase 3: Benchmark & Trials Models
# ==========================================
class AggregateResponse(BaseModel):
    status: str
    message: str
    paid: str
    receipt_id: str
    next_action: Optional[NextAction] = None

class PerformanceStats(BaseModel):
    score: float
    latency_sec: float
    retry_count: float

class CompareAnalytics(BaseModel):
    critical_bottleneck: str
    advice: str

class CompareResponse(BaseModel):
    status: str
    trial_id: str
    paid: str
    receipt_id: str
    my_performance: PerformanceStats
    top_10_average: PerformanceStats
    analytics: CompareAnalytics

class BenchmarkOverviewResponse(BaseModel):
    status: str
    message: str
    benchmark: Dict[str, Any]
    next_action: Optional[NextAction] = None

# ==========================================
# ⛩️ Phase 4: Missionary Work (Monzen DNS) Models
# ==========================================
class MonzenTraceResponse(BaseModel):
    status: str
    action_type: str
    trace_id: str
    recorded_hash: str
    timestamp: int
    virtue_earned: int
    verification_status: Optional[str] = None
    verification_method: Optional[str] = None
    proof_reference: Optional[str] = None
    message: str
    next_action: Optional[Dict[str, Any]] = None

class SiteRanking(BaseModel):
    domain: str
    total_verifications: int
    unique_agents: int
    last_verified_at: int

class MonzenMetricsResponse(BaseModel):
    status: str
    tier: str
    limit_applied: int
    rankings: List[SiteRanking]
    next_action: Optional[NextAction] = None

class MonzenGraphResponse(BaseModel):
    status: str
    tier: str
    payment_scheme_used: str
    data: Dict[str, Any]
    next_action: Optional[NextAction] = None