import uuid
import time
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from urllib.parse import urlparse

class ChallengeSource(str, Enum):
    STANDARD_X402 = "payment_required_header"  # PAYMENT-REQUIRED
    STANDARD_WWW = "www_authenticate"         # WWW-Authenticate (L402/MPP)
    LEGACY_CUSTOM = "legacy_custom_header"    # x-402-payment-required
    BODY_CHALLENGE = "body_challenge"         # JSON Body

class AttestationSource(str, Enum):
    SERVER_JWS = "server_attested"             # PAYMENT-RESPONSE 由来
    CLIENT_REPORTED = "self_reported"         # クライアント自己申告 (txHash 等)

# ==========================================
# v1.9.5: Observation Layer Models (NEW)
# ==========================================

class SettlementOption(BaseModel):
    """
    v1.9.5: A safely redacted, structured representation of a single payment option
    presented by an HTTP 402 or agent-commerce surface.
    """
    rail: str  # "x402", "L402", "MPP", "unknown"
    scheme: Optional[str] = None
    network: Optional[str] = None
    chain_family: Optional[str] = None  # "evm", "svm", "lightning", "unknown"
    chain_name_hint: Optional[str] = None
    asset: Optional[str] = None
    asset_symbol_hint: Optional[str] = None
    amount: Optional[str] = None
    amount_atomic: Optional[str] = None
    pay_to: Optional[str] = None
    source: Optional[str] = None
    raw_requirement_fingerprint: Optional[str] = None
    execution_support: Optional[str] = None  # "supported", "observe_only", "unsupported", "unknown"
    selected: bool = False
    selection_reason: Optional[str] = None
    # --- v1.9.7: Deferred Settlement Fields ---
    settlement_model: Optional[str] = None
    authorization_artifact: Optional[str] = None
    finality_model: Optional[str] = None
    requires_channel_state: Optional[bool] = None
    deferred_settlement: Optional[bool] = None

class ObservatoryMetadata(BaseModel):
    """
    v1.9.5: Local advisory metadata denoting LN Church Observatory rules.
    Guarantees opt-in awareness without executing automatic submissions.
    """
    submitted: bool = False
    submission_mode: str = "opt_in_only"
    description: str = "LN Church Observatory can collect redacted observations and interoperability evidence for HTTP 402 payment surfaces."
    canonical_url: str = "https://kari.mayim-mayim.com/for-agents.html"

# ==========================================
# v1.4 / v1.5 / v1.5.9: Trust, Outcome & Evidence Layer Models
# ==========================================

class TrustDecision(BaseModel):
    """支払い前の相手先信用評価結果"""
    is_trusted: bool
    reason: str = ""

class L402ExecutionReport(BaseModel):
    """L402 Delegate 実行後の詳細レポート"""
    delegate_source: str = "native"  # "native" | "lightninglabs"
    authorization_value: str
    preimage: Optional[str] = None
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    amount_sats: Optional[int] = None
    endpoint: Optional[str] = None
    payment_performed: bool = True
    cached_token_used: bool = False
    verification_status: str = "verified"
    raw_receipt_ref: Optional[dict] = None

class OutcomeSummary(BaseModel):
    """決済後の期待状態（Outcome）の評価結果"""
    is_success: bool
    observed_state: str = ""
    message: str = ""
    external_evidence: dict = Field(default_factory=dict)

class SponsoredAccessEvidence(BaseModel):
    """v1.8.4: Sponsored Access (Grant) の実行証跡"""
    access_path: str = "sponsored_grant"
    authorization_artifact: str = "scoped_grant"
    settlement_rail: str = "none"

    grant_jti: Optional[str] = None
    issuer: Optional[str] = None
    sponsor_id: Optional[str] = None
    entitlement: Optional[str] = None

    scope_routes: List[str] = Field(default_factory=list)
    scope_methods: List[str] = Field(default_factory=list)

    local_diagnostic_ok: Optional[bool] = None
    local_diagnostic_failure_class: Optional[str] = None
    local_diagnostic_reason: Optional[str] = None

    server_consumed: Optional[bool] = None
    receipt_present: bool = False
    verify_token_present: bool = False

    token_hash: Optional[str] = None

class SandboxEvidence(BaseModel):
    """v1.8.4: Sandboxの実行およびReport結果の証跡"""
    schema_version: str = "sandbox_evidence.v1"
    evidence_scope: str = "sandbox_internal"

    run_id: Optional[str] = None
    scenario_id: Optional[str] = None
    rail: Optional[str] = None
    payment_intent: Optional[str] = None
    payment_method: Optional[str] = None
    authorization_scheme: Optional[str] = None
    draft_shape: Optional[str] = None
    network: Optional[str] = None
    asset: Optional[str] = None

    canonical_hash_expected: Optional[str] = None
    canonical_hash_actual: Optional[str] = None
    canonical_hash_matched: Optional[bool] = None

    payment_receipt_present: Optional[bool] = None
    server_payment_receipt_present: Optional[bool] = None
    client_reported_payment_receipt_present: Optional[bool] = None
    payment_receipt_id: Optional[str] = None

    verification_status: Optional[str] = None

    report_interop_url: Optional[str] = None
    logs_url: Optional[str] = None

    interop_token_hash: Optional[str] = None

class SandboxCorpusCandidate(BaseModel):
    """v1.8.5: Sandbox Evidence Corpus Candidate Model"""
    schema_version: str = "sandbox_corpus_candidate.v1"
    source_scope: str = "sandbox_internal"
    evidence_scope: str = "sandbox_internal"

    run_id: Optional[str] = None
    scenario_id: Optional[str] = None
    rail: Optional[str] = None
    payment_intent: Optional[str] = None

    network: Optional[str] = None
    asset: Optional[str] = None
    payment_method: Optional[str] = None
    authorization_scheme: Optional[str] = None
    draft_shape: Optional[str] = None

    verification_status: Optional[str] = None
    canonical_hash_matched: Optional[bool] = None

    payment_receipt_present: Optional[bool] = None
    server_payment_receipt_present: Optional[bool] = None
    client_reported_payment_receipt_present: Optional[bool] = None

    corpus_eligible: Optional[bool] = None
    exclusion_reason: Optional[str] = None

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
    trust_decision: Optional[Any] = None # Forward ref回避のためAny
    receipt_summary: Optional[dict] = None
    outcome: Optional[Any] = None
    error_message: Optional[str] = None
    navigation_source: Optional[str] = None
    session_spend_delta_usd: Optional[float] = None
    delegate_source: str = "native"
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    cached_token_used: bool = False
    payment_performed: bool = True
    
    # --- v1.8.4 新規追加 (Widening) ---
    sponsored_access: Optional[SponsoredAccessEvidence] = None
    sandbox: Optional[SandboxEvidence] = None

class ExecutionContext(BaseModel):
    """軽量な意図とセッションのコンテキスト"""
    intent_label: str = "default_intent"
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hints: dict = Field(default_factory=dict)
    # v1.5.1 Experimental: 明示的かつ型安全な Evidence 引き回し用フィールド
    past_evidence: Optional[List[PaymentEvidenceRecord]] = None
    # v1.5.9 Update: セッション予算が Evidence から復元済みかを示すフラグ（二重復元防止）
    session_budget_restored: bool = False

class ParsedChallenge(BaseModel):
    scheme: str
    network: str
    amount: float
    asset: str
    parameters: Dict[str, Any]
    source: ChallengeSource                    
    raw_header: Optional[str] = None
    # MPP / Payment draft telemetry
    draft_shape: Optional[str] = None
    payment_method: Optional[str] = None
    payment_intent: Optional[str] = None
    request_b64_present: bool = False
    decoded_request_valid: bool = False

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
    # 💡 新規追加: 失敗時のテレメトリ伝播用
    credential_shape: Optional[str] = None
    failure_reason: Optional[str] = None

class EvidenceRepository:
    """v1.5.1 / v1.5.9 Experimental: Evidenceの保存と取得を行うための抽象インターフェース"""
    
    def export_evidence(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        pass

    def import_evidence(self, target_url: str, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return []

    def import_session_evidence(self, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return []

    async def export_evidence_async(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        self.export_evidence(record, context)

    async def import_evidence_async(self, target_url: str, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return self.import_evidence(target_url, context)

    async def import_session_evidence_async(self, context: ExecutionContext) -> List[PaymentEvidenceRecord]:
        return self.import_session_evidence(context)

@dataclass
class PaymentPolicy:
    """
    エージェントの自律経済行動を制限するガードレール (Policy Layer)
    """
    allowed_schemes: List[str] = field(default_factory=lambda: [
        "L402", "x402", "lnc-evm-relay", "lnc-evm-transfer", "lnc-solana-transfer", "MPP", "Payment", "exact"
    ])
    allowed_assets: List[str] = field(default_factory=lambda: ["SATS", "USDC", "JPYC"])
    allowed_networks: Optional[List[str]] = None  # v1.7.0: ネットワーク識別子による制御を追加
    max_spend_per_tx_usd: float = 5.0
    max_spend_per_session_usd: float = 10.0
    allowed_hosts: Optional[List[str]] = None
    blocked_hosts: List[str] = field(default_factory=list)
    _session_spent_usd: float = field(default=0.0, repr=False)

class SettlementReceipt(BaseModel):
    receipt_id: str
    scheme: str
    settled_amount: float
    asset: str
    network: str
    proof_reference: str
    receipt_token: Optional[str] = None
    verification_status: str = "verified"
    source: AttestationSource = AttestationSource.CLIENT_REPORTED
    delegate_source: str = "native"
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    cached_token_used: bool = False
    payment_performed: bool = True
    endpoint: Optional[str] = None

class AssetType(str, Enum):
    JPYC = "JPYC"
    USDC = "USDC"
    SATS = "SATS"
    FAUCET_CREDIT = "FAUCET_CREDIT"
    GRANT_CREDIT = "GRANT_CREDIT"

class SchemeType(str, Enum):
    # Standard Protocols
    l402 = "L402"
    mpp = "MPP"
    x402 = "x402"
    grant = "grant"
    faucet = "faucet"
    
    # LN Church Canonical Routings
    lnc_evm_relay = "lnc-evm-relay"
    lnc_evm_transfer = "lnc-evm-transfer"
    lnc_solana_transfer = "lnc-solana-transfer"
    
    # @deprecated
    x402_direct = "x402-direct"
    x402_solana = "x402-solana"


class PaymentAuth(BaseModel):
    scheme: SchemeType
    proof: str
    chainId: Optional[str] = None
    agentId: Optional[str] = None

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
    agentId: Optional[str] = None  
    verify_token: str
    probe_verified: Optional[bool] = False
    proof_class: Optional[str] = None

class AgentIdentity(BaseModel):
    status: str
    public_profile_url: str
    agent_id: Optional[str] = None

# ==========================================
# ⛩️ Phase 1, 2, 3, 4 Models (Omikuji, Confession, etc.)
# ==========================================
class OmikujiResponse(BaseModel):
    status: str
    result: str
    message: str
    tx_ref: str
    receipt: OmikujiReceipt
    paid: str

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
    next_action: Optional[NextAction] = None

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

# ==========================================
# 🔒 Internal Models (v1.6+ Access Selection)
# ==========================================
class _ExecutionUnlock(str, Enum):
    SETTLEMENT_PROOF = "settlement_proof"
    ENTITLEMENT_PROOF = "entitlement_proof"

class _FundingPolicy(str, Enum):
    SELF_FUNDED = "self_funded"
    SUBSIDIZED = "subsidized"
    FULLY_SPONSORED = "fully_sponsored"

class _EntitlementKind(str, Enum):
    FAUCET = "faucet"
    GRANT = "grant"

class _ExecutionAccessPlan(BaseModel):
    unlock: _ExecutionUnlock
    funding_policy: _FundingPolicy
    entitlement_kind: Optional[_EntitlementKind] = None
    settlement_scheme: str
    settlement_asset: str
    selected_reason: str = ""

# ==========================================
# 🧪 Sandbox, Interop & Diagnostic Models
# ==========================================
class InteropRunResult(BaseModel):
    ok: bool
    target_url: str
    run_id: str
    scenario_id: str
    executor_mode: str
    delegate_source: str
    canonical_hash_expected: str
    canonical_hash_observed: str
    canonical_hash_matched: bool
    report_status_code: int
    report_accepted: bool
    payment_performed: bool
    cached_token_used: bool
    receipt_id: Optional[str] = None
    raw_report_response: Dict[str, Any]

class ExternalProtocolRunResult(BaseModel):
    ok: bool
    target_url: str
    scenario_id: str
    verification_scope: str = "client_attested_external"
    comparison_basis: str = "protocol_success"
    executor_mode: str
    delegate_source: str
    status_code_after_payment: int
    payment_performed: bool
    cached_token_used: bool
    receipt_id: Optional[str] = None
    latency_ms: int
    response_shape_ok: bool
    response_excerpt: str
    protocol_success: bool
    schema_check_reason: str = ""
    error_stage: Optional[str] = None
    error_reason: Optional[str] = None
    suspected_failure_origin: str = "unknown" 
    upstream_status_code: Optional[int] = None
    upstream_host_excerpt: Optional[str] = None
    debug_logs: List[str] = Field(default_factory=list)

class CorpusReplayResult(BaseModel):
    ok: bool
    corpus_id: str
    replay_type: str
    expected_action: str
    observed_action: str
    challenge_status_code: Optional[int] = None
    descriptor_schema_version: Optional[str] = None
    source_observation_id: Optional[str] = None
    parsed_scheme: Optional[str] = None
    parsed_rail: Optional[str] = None
    parsed_payment_intent: Optional[str] = None
    parsed_draft_shape: Optional[str] = None
    failure_reason: Optional[str] = None
    raw_descriptor: Optional[Dict[str, Any]] = None
    raw_challenge_body: Optional[Dict[str, Any]] = None

class GrantSignalObservation(BaseModel):
    """
    v1.11.2: A sidecar observation model for detecting grant-like incentive signals 
    (faucet, trial credit, promotional credit) on external sites.
    Strictly unverified: does not guarantee redeemability or availability.
    """
    detected: bool = False
    confidence: str = "none"  # none | low | medium | high

    signal_types: List[str] = Field(default_factory=list)
    source_kinds: List[str] = Field(default_factory=list)
    detected_terms: List[str] = Field(default_factory=list)
    detected_fields: List[str] = Field(default_factory=list)

    machine_readable: bool = False
    redeemability_verified: bool = False
    availability_verified: bool = False

    redemption_endpoint_present: bool = False
    verification_endpoint_present: bool = False
    eligibility_declared: bool = False
    scope_declared: bool = False
    expiration_declared: bool = False
    transferability_declared: Optional[bool] = None
    requires_identity: Optional[bool] = None

    recommended_action: str = "observe_only"
    diagnostic_class: str = "grant_like_signal_observed"

    not_a_recommendation: bool = True
    not_a_verdict: bool = True
    unassessed_is_not_failed: bool = True

    reason: str = "Grant-like signals are observed only. Redeemability and availability are not verified."

class InspectResult(BaseModel):
    """CLI inspect コマンド用の実行結果モデル (v1.9.5: Observation Layer 統合)"""
    ok: bool
    url: str
    http_status: Optional[int] = None
    rails_detected: List[str] = Field(default_factory=list)
    
    # --- v1.9.0: Commerce Surface vs Settlement Rail ---
    surface_type: Optional[str] = None
    surfaces_detected: List[str] = Field(default_factory=list)
    settlement_rails_detected: List[str] = Field(default_factory=list)
    detection_confidence: Optional[str] = None
    detection_reason: Optional[str] = None
    unsupported_reason: Optional[str] = None

    # --- v1.9.1: Guided Handoff Fields ---
    handoff_mode: Optional[str] = None
    approval_required: Optional[bool] = None
    ask_site_for: List[str] = Field(default_factory=list)
    do_not: List[str] = Field(default_factory=list)
    required_evidence: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    operator_approval_reason: Optional[str] = None

    # --- v1.9.5: Settlement Options Observation ---
    settlement_options: List[SettlementOption] = Field(default_factory=list)
    selected_settlement_option: Optional[SettlementOption] = None
    ln_church_observatory: Optional[ObservatoryMetadata] = None

    challenge_source: Optional[str] = None
    payment_intent: Optional[str] = None
    draft_shape: Optional[str] = None
    recommended_action: str
    will_execute_payment: bool = False
    reason: str = ""
    next_command: Optional[str] = None
    error_stage: Optional[str] = None
    failure_reason: Optional[str] = None
    diagnostic_class: Optional[str] = None
    failure_class: Optional[str] = None

    commerce_protocol: Optional[str] = None
    commerce_intent: Optional[str] = None
    commerce_transport: Optional[str] = None
    authorization_artifact: Optional[str] = None
    settlement_rail: Optional[str] = None
    settlement_method: Optional[str] = None
    network: Optional[str] = None
    broker_required: Optional[bool] = None
    classification_confidence: Optional[str] = None
    
    # 互換用エイリアス
    app_protocol: Optional[str] = None
    app_intent: Optional[str] = None
    app_transport: Optional[str] = None

    # --- v1.11.2: Grant-like Signal Detection Sidecar ---
    grant_signal_detected: bool = False
    grant_signals: GrantSignalObservation = Field(default_factory=GrantSignalObservation)

class X402ExactDiagnosticResult(BaseModel):
    ok: bool
    scenario_id: str
    endpoint: str
    network: Optional[str] = None
    asset: Optional[str] = None
    token_address: Optional[str] = None
    draft_shape: Optional[str] = None
    settlement_model: str = "post_settlement_verification"
    challenge_shape_ok: bool = False
    expected_rejection: bool = False
    rejection_reason: Optional[str] = None
    recommended_action: str = "observe_only"
    diagnostic_class: Optional[str] = None
    failure_class: Optional[str] = None

class GrantDiagnostics(BaseModel):
    ok: bool
    usable: bool
    failure_class: Optional[str] = None
    reason: Optional[str] = None
    
    grant_jti: Optional[str] = None
    issuer: Optional[str] = None
    sponsor_id: Optional[str] = None
    subject: Optional[str] = None
    audience: Optional[Union[str, List[str]]] = None
    entitlement: Optional[str] = None
    
    scope_routes: List[str] = Field(default_factory=list)
    scope_methods: List[str] = Field(default_factory=list)
    
    asset: Optional[str] = None
    amount: Optional[float] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None

    access_path: str = "sponsored_grant"
    authorization_artifact: str = "scoped_grant"
    settlement_rail: str = "none"

    recommended_action: str = "use_grant"
    fallback_action: Optional[str] = None

class PaymentFailureRecord(BaseModel):
    schema_version: str = "ln_church_agent.payment_failure_record.v1"
    
    # identity / target
    record_id: str
    observed_at: int
    endpoint: str
    target_domain: str
    method: str

    # protocol context
    rail: str
    scheme: Optional[str] = None
    network: str
    asset: str
    authorization_scheme: Optional[str] = None
    draft_shape: Optional[str] = None
    payment_intent: Optional[str] = None

    # challenge summary
    challenge_fingerprint_before: Optional[str] = None
    challenge_fingerprint_after: Optional[str] = None
    challenge_fingerprint_changed: bool = False
    changed_fields: List[str] = []
    selected_requirement_fingerprint: Optional[str] = None

    # attempt context
    attempted: bool = True
    attempt_count: int = 1
    retry_count: int = 0
    client_used: str = "ln-church-agent"
    secondary_client_used: Optional[str] = None

    # outcome
    final_http_status: Optional[int] = None
    failure_class: str
    failure_subclass: Optional[str] = None
    error_stage: Optional[str] = None
    server_message_excerpt: Optional[str] = None
    client_error_excerpt: Optional[str] = None

    # evidence / trust
    reproducibility: str = "unknown"
    evidence_strength: str = "low"
    confidence: str = "low"
    operator_verified: bool = False

    # payment status
    payment_performed: bool = False
    settlement_confirmed: bool = False
    payment_receipt_present: bool = False

    # publication safety
    safe_to_publish: bool = True
    redaction_applied: bool = True
    public_notes: Optional[str] = None