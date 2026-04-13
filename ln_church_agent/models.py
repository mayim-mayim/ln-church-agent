import uuid
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import time

class ChallengeSource(str, Enum):
    STANDARD_X402 = "payment_required_header"  # PAYMENT-REQUIRED
    STANDARD_WWW = "www_authenticate"         # WWW-Authenticate (L402/MPP)
    LEGACY_CUSTOM = "legacy_custom_header"    # x-402-payment-required
    BODY_CHALLENGE = "body_challenge"         # JSON Body

class AttestationSource(str, Enum):
    SERVER_JWS = "server_attested"             # PAYMENT-RESPONSE 由来
    CLIENT_REPORTED = "self_reported"         # クライアント自己申告 (txHash 等)

# ==========================================
# v1.4 / v1.5: Trust, Outcome & Evidence Layer Models
# (※依存順序による前方参照エラーを防ぐためトポロジカルに配置)
# ==========================================

class TrustDecision(BaseModel):
    """支払い前の相手先信用評価結果"""
    is_trusted: bool
    reason: str = ""

class OutcomeSummary(BaseModel):
    """決済後の期待状態（Outcome）の評価結果"""
    is_success: bool
    observed_state: str = ""
    message: str = ""
    external_evidence: dict = Field(default_factory=dict)

class PaymentEvidenceRecord(BaseModel):
    """v1.5.1 Experimental: 支払い判断と結果の証跡レコード"""
    timestamp: float = Field(default_factory=time.time)
    session_id: str
    correlation_id: str
    target_url: str
    method: str
    scheme: Optional[str] = None
    asset: Optional[str] = None
    amount: Optional[float] = None
    trust_decision: Optional[TrustDecision] = None
    receipt_summary: Optional[dict] = None
    outcome: Optional[OutcomeSummary] = None
    error_message: Optional[str] = None

class ExecutionContext(BaseModel):
    """軽量な意図とセッションのコンテキスト"""
    intent_label: str = "default_intent"
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hints: dict = Field(default_factory=dict)
    # v1.5.1 Experimental: 明示的かつ型安全な Evidence 引き回し用フィールド
    past_evidence: Optional[List[PaymentEvidenceRecord]] = None

class ParsedChallenge(BaseModel):
    scheme: str
    network: str
    amount: float
    asset: str
    parameters: Dict[str, Any]
    source: ChallengeSource                    # 解析元を記録
    raw_header: Optional[str] = None

class TrustEvidence(BaseModel):
    """評価の根拠を束ねるコンテナ（Source-Agnostic）"""
    url: str
    challenge: ParsedChallenge
    host_metadata: dict = Field(default_factory=dict)
    agent_hints: dict = Field(default_factory=dict)

class ExecutionResult(BaseModel):
    response: dict
    final_url: str
    retry_count: int = 0
    settlement_receipt: Optional[Any] = None
    used_scheme: Optional[str] = None
    used_asset: Optional[str] = None
    verification_status: Optional[str] = None
    outcome: Optional[OutcomeSummary] = None

class EvidenceRepository:
    """v1.5.1 Experimental: Evidenceの保存と取得を行うための抽象インターフェース"""
    def export_evidence(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        pass

    def import_evidence(self, target_url: str, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return []

    async def export_evidence_async(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        self.export_evidence(record, context)

    async def import_evidence_async(self, target_url: str, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return self.import_evidence(target_url, context)

@dataclass
class PaymentPolicy:
    """
    エージェントの自律経済行動を制限するガードレール (Policy Layer)
    v1.3.0: セッション上限とホスト制限を追加し、ハルシネーションによる資金枯渇を防止。
    """
    # ★ 改修: デフォルトの許容スキームを Canonical な名称に変更
    allowed_schemes: List[str] = field(default_factory=lambda: ["L402", "x402", "lnc-evm-relay", "lnc-evm-transfer", "lnc-solana-transfer", "MPP"])
    allowed_assets: List[str] = field(default_factory=lambda: ["SATS", "USDC", "JPYC"])
    max_spend_per_tx_usd: float = 5.0 # デフォルトで1回5ドルを上限とする安全装置
    # --- v1.3.0 Additions ---
    max_spend_per_session_usd: float = 10.0
    allowed_hosts: Optional[List[str]] = None
    blocked_hosts: List[str] = field(default_factory=list)
    
    # 内部管理用セッション消費額
    _session_spent_usd: float = field(default=0.0, repr=False)

class SettlementReceipt(BaseModel):
    receipt_id: str
    scheme: str
    settled_amount: float
    asset: str
    network: str
    proof_reference: str
    receipt_token: Optional[str] = None       # サーバー返却の JWS 等
    verification_status: str = "verified"
    source: AttestationSource = AttestationSource.CLIENT_REPORTED

class AssetType(str, Enum):
    JPYC = "JPYC"
    USDC = "USDC"
    SATS = "SATS"
    FAUCET_CREDIT = "FAUCET_CREDIT"

class SchemeType(str, Enum):
    # Standard Protocols
    l402 = "L402"
    mpp = "MPP"
    x402 = "x402"
    
    # LN Church Canonical Routings
    lnc_evm_relay = "lnc-evm-relay"
    lnc_evm_transfer = "lnc-evm-transfer"
    lnc_solana_transfer = "lnc-solana-transfer"
    
    # --- Legacy Aliases (DEPRECATED: Mapped to lnc-* equivalents internally) ---
    # @deprecated: Use lnc_evm_transfer instead.
    x402_direct = "x402-direct"
    # @deprecated: Use lnc_solana_transfer instead.
    x402_solana = "x402-solana"


class PaymentAuth(BaseModel):
    # ★ 改修: SchemeType の参照を維持しつつ、CAIP-2対応の chainId や agentId を追加
    scheme: SchemeType
    proof: str
    chainId: Optional[str] = None # CAIP-2 ネットワーク識別子 (e.g. "eip155:137") を許容するため str に
    agentId: Optional[str] = None # lnc-solana-transfer の要件

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