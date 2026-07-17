import uuid
import time
from enum import Enum
from pydantic import BaseModel, Field, PrivateAttr
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from urllib.parse import urlparse
from decimal import Decimal
import threading

class ChallengeSource(str, Enum):
    STANDARD_X402 = "payment_required_header"
    STANDARD_WWW = "www_authenticate"
    LEGACY_CUSTOM = "legacy_custom_header"
    BODY_CHALLENGE = "body_challenge"

class AttestationSource(str, Enum):
    SERVER_JWS = "server_attested"
    UNSIGNED_SERVER = "server_asserted_unsigned"
    CLIENT_REPORTED = "self_reported"

class SettlementOption(BaseModel):
    rail: str
    scheme: Optional[str] = None
    network: Optional[str] = None
    chain_family: Optional[str] = None
    chain_name_hint: Optional[str] = None
    asset: Optional[str] = None
    asset_symbol_hint: Optional[str] = None
    amount: Optional[str] = None
    amount_atomic: Optional[str] = None
    pay_to: Optional[str] = None
    source: Optional[str] = None
    raw_requirement_fingerprint: Optional[str] = None
    execution_support: Optional[str] = None
    selected: bool = False
    selection_reason: Optional[str] = None
    settlement_model: Optional[str] = None
    authorization_artifact: Optional[str] = None
    finality_model: Optional[str] = None
    requires_channel_state: Optional[bool] = None
    deferred_settlement: Optional[bool] = None

class ObservatoryMetadata(BaseModel):
    submitted: bool = False
    submission_mode: str = "opt_in_only"
    description: str = "LN Church Observatory can collect redacted observations and interoperability evidence for HTTP 402 payment surfaces."
    canonical_url: str = "https://kari.mayim-mayim.com/for-agents.html"

class TrustDecision(BaseModel):
    is_trusted: bool
    reason: str = ""

class L402ExecutionReport(BaseModel):
    delegate_source: str = "native"
    authorization_value: str = Field(repr=False)
    preimage: Optional[str] = Field(default=None, repr=False)
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    amount_sats: Optional[int] = None
    endpoint: Optional[str] = None
    payment_performed: bool = True
    cached_token_used: bool = False
    verification_status: str = "verified"
    raw_receipt_ref: Optional[dict] = None

class OutcomeSummary(BaseModel):
    is_success: bool
    observed_state: str = ""
    message: str = ""
    external_evidence: dict = Field(default_factory=dict)

class SponsoredAccessEvidence(BaseModel):
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
    timestamp: float = Field(default_factory=time.time)
    session_id: str
    correlation_id: str
    target_url: str
    method: str
    scheme: Optional[str] = None
    asset: Optional[str] = None
    amount: Optional[float] = None
    trust_decision: Optional[Any] = None
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
    sponsored_access: Optional[SponsoredAccessEvidence] = None
    sandbox: Optional[SandboxEvidence] = None

class ExecutionContext(BaseModel):
    intent_label: str = "default_intent"
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hints: dict = Field(default_factory=dict)
    past_evidence: Optional[List[PaymentEvidenceRecord]] = None
    session_budget_restored: bool = False

    _session_budget_restored: bool = PrivateAttr(default=False)
    _payment_executed: bool = PrivateAttr(default=False)
    _idempotency_key: Optional[str] = PrivateAttr(default=None)
    _logical_operation_id: Optional[str] = PrivateAttr(default=None)
    _origin_idempotency_keys: Dict[str, str] = PrivateAttr(default_factory=dict)
    _payment_states: Dict[str, str] = PrivateAttr(default_factory=dict)
    _payment_identities: Dict[str, str] = PrivateAttr(default_factory=dict)
    _ambiguous_reservations: Dict[str, Decimal] = PrivateAttr(default_factory=dict)
    _known_settled_ambiguities: set = PrivateAttr(default_factory=set)
    _navigation_urls: set = PrivateAttr(default_factory=set)
    _navigation_hops: int = PrivateAttr(default=0)
    _navigation_states: Dict[str, Any] = PrivateAttr(default_factory=dict)
    _navigation_pins: Dict[str, Any] = PrivateAttr(default_factory=dict)
    _payment_state_lock: threading.RLock = PrivateAttr(default_factory=threading.RLock)

    def model_post_init(self, __context: Any) -> None:
        """Bridge the v1.16.1 public flag to the private runtime state."""
        self._session_budget_restored = self.session_budget_restored

    def get_payment_state(self, fingerprint: str) -> str:
        with self._payment_state_lock:
            return self._payment_states.get(fingerprint, "not_started")

    def set_payment_state(self, fingerprint: str, state: str):
        with self._payment_state_lock:
            self._payment_states[fingerprint] = state

    def list_payment_states(self) -> Dict[str, str]:
        """Return a snapshot suitable for ambiguity/status recovery tooling."""
        with self._payment_state_lock:
            return dict(self._payment_states)

class ParsedChallenge(BaseModel):
    scheme: str
    network: str
    amount: float
    asset: str
    parameters: Dict[str, Any]
    source: ChallengeSource
    raw_header: Optional[str] = None
    draft_shape: Optional[str] = None
    payment_method: Optional[str] = None
    payment_intent: Optional[str] = None
    request_b64_present: bool = False
    decoded_request_valid: bool = False
    _invoice_msats: Optional[int] = PrivateAttr(default=None)
    _atomic_amount: Optional[str] = PrivateAttr(default=None)
    _canonical_requirement: Optional[Any] = PrivateAttr(default=None)
    _signer_requirement: Optional[Any] = PrivateAttr(default=None)
    _approved_requirement_hash: Optional[str] = PrivateAttr(default=None)

class CanonicalPaymentRequirement(BaseModel):
    """P0-B: PolicyとSignerが合意するための正規化された支払要件"""
    scheme: str
    network: str
    chain_id: Optional[int] = None
    asset: str
    token_address_or_mint: str
    decimals: int
    atomic_amount: str
    human_amount_decimal: Decimal
    pay_to: str
    source_origin: str

class TrustEvidence(BaseModel):
    url: str
    challenge: ParsedChallenge
    host_metadata: dict = Field(default_factory=dict)
    agent_hints: dict = Field(default_factory=dict)

class ExecutionResult(BaseModel):
    response: dict
    final_url: str
    retry_count: int = 0
    response_headers: Dict[str, str] = Field(default_factory=dict)
    settlement_receipt: Optional[Any] = None
    used_scheme: Optional[str] = None
    used_asset: Optional[str] = None
    verification_status: Optional[str] = None
    outcome: Optional[OutcomeSummary] = None
    credential_shape: Optional[str] = None
    failure_reason: Optional[str] = None

class EvidenceRepository:
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
    allowed_schemes: List[str] = field(default_factory=lambda: [
        "L402", "x402", "lnc-evm-relay", "lnc-evm-transfer", "lnc-solana-transfer", "MPP", "Payment", "exact"
    ])
    allowed_assets: List[str] = field(default_factory=lambda: ["SATS", "USDC", "JPYC"])
    allowed_networks: Optional[List[str]] = None
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
    proof_reference: Optional[str]
    # Never retain the raw PAYMENT-RESPONSE / Payment-Receipt bearer-like
    # value.  Persist only its one-way digest and parsed claims/state.
    receipt_token_hash: Optional[str] = None
    receipt_claims: Optional[Dict[str, str]] = None
    verification_status: str = "unverified"
    source: AttestationSource = AttestationSource.CLIENT_REPORTED
    present: bool = False
    server_asserted: bool = False
    signature_verified: bool = False
    settlement_verified: bool = False
    delivered: bool = False
    receipt_format: Optional[str] = None
    receipt_error: Optional[str] = None
    payment_id: Optional[str] = None
    requirement_hash: Optional[str] = None
    delegate_source: str = "native"
    payment_hash: Optional[str] = None
    fee_sats: Optional[int] = None
    cached_token_used: bool = False
    payment_performed: bool = True
    endpoint: Optional[str] = None

    @property
    def receipt_token(self) -> None:
        """Deprecated compatibility accessor; raw receipt tokens are discarded.

        P0-2 intentionally no longer stores or serializes the bearer-like raw
        ``PAYMENT-RESPONSE`` value.  Existing callers may continue reading this
        attribute while migrating to ``receipt_token_hash`` and the explicit
        receipt-state fields.
        """

        return None

class AssetType(str, Enum):
    JPYC = "JPYC"
    USDC = "USDC"
    SATS = "SATS"
    FAUCET_CREDIT = "FAUCET_CREDIT"
    GRANT_CREDIT = "GRANT_CREDIT"

class SchemeType(str, Enum):
    l402 = "L402"
    mpp = "MPP"
    x402 = "x402"
    grant = "grant"
    faucet = "faucet"
    lnc_evm_relay = "lnc-evm-relay"
    lnc_evm_transfer = "lnc-evm-transfer"
    lnc_solana_transfer = "lnc-solana-transfer"
    x402_direct = "x402-direct"
    x402_solana = "x402-solana"

class PaymentAuth(BaseModel):
    scheme: SchemeType
    proof: str
    chainId: Optional[str] = None
    agentId: Optional[str] = None

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
    detected: bool = False
    confidence: str = "none"
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
    ok: bool
    url: str
    http_status: Optional[int] = None
    rails_detected: List[str] = Field(default_factory=list)
    surface_type: Optional[str] = None
    surfaces_detected: List[str] = Field(default_factory=list)
    settlement_rails_detected: List[str] = Field(default_factory=list)
    detection_confidence: Optional[str] = None
    detection_reason: Optional[str] = None
    unsupported_reason: Optional[str] = None
    handoff_mode: Optional[str] = None
    approval_required: Optional[bool] = None
    ask_site_for: List[str] = Field(default_factory=list)
    do_not: List[str] = Field(default_factory=list)
    required_evidence: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    operator_approval_reason: Optional[str] = None
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
    app_protocol: Optional[str] = None
    app_intent: Optional[str] = None
    app_transport: Optional[str] = None
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
    record_id: str
    observed_at: int
    endpoint: str
    target_domain: str
    method: str
    rail: str
    scheme: Optional[str] = None
    network: str
    asset: str
    authorization_scheme: Optional[str] = None
    draft_shape: Optional[str] = None
    payment_intent: Optional[str] = None
    challenge_fingerprint_before: Optional[str] = None
    challenge_fingerprint_after: Optional[str] = None
    challenge_fingerprint_changed: bool = False
    changed_fields: List[str] = []
    selected_requirement_fingerprint: Optional[str] = None
    attempted: bool = True
    attempt_count: int = 1
    retry_count: int = 0
    client_used: str = "ln-church-agent"
    secondary_client_used: Optional[str] = None
    final_http_status: Optional[int] = None
    failure_class: str
    failure_subclass: Optional[str] = None
    error_stage: Optional[str] = None
    server_message_excerpt: Optional[str] = None
    client_error_excerpt: Optional[str] = None
    reproducibility: str = "unknown"
    evidence_strength: str = "low"
    confidence: str = "low"
    operator_verified: bool = False
    payment_performed: bool = False
    settlement_confirmed: bool = False
    payment_receipt_present: bool = False
    safe_to_publish: bool = True
    redaction_applied: bool = True
    public_notes: Optional[str] = None

OBSERVATION_PROVENANCE_SCHEMA_VERSION = "ln_church.observation_provenance.v1"
PROTOCOL_ROLES_SCHEMA_VERSION = "ln_church.protocol_roles.v1"
VERIFICATION_COST_VECTOR_SCHEMA_VERSION = "ln_church.verification_cost_vector.v1"
VERIFICATION_COST_FORMULA_VERSION = "ln_church.verification_cost_formula.v1"
READ_MODEL_REVISION = "v1.13.0"

def build_observation_provenance(reporter_verification_mix: dict) -> dict:
    normalized = {"self_reported": 0, "key_control_verified": 0, "expired": 0, "unknown": 0}
    normalized.update(reporter_verification_mix or {})
    return {
        "schema_version": OBSERVATION_PROVENANCE_SCHEMA_VERSION,
        "reporter_verification_mix": dict(normalized),
        "attempt_count_by_reporter_verification_status": dict(normalized),
        "not_a_trust_score": True,
        "not_a_recommendation": True,
        "not_a_verdict": True,
        "not_a_truth_proof": True
    }

def build_protocol_role_observation(
    role: str, protocol: str, capability_observations: dict, highest_observed_stage: str = "unknown", last_observed_at: Optional[str] = None
) -> dict:
    valid_roles = {"data_access", "commerce_interaction", "payment_authorization", "payment_settlement", "agent_interop", "fallback_operation"}
    if role not in valid_roles: raise ValueError(f"Invalid role: {role}")
    DEFAULT_CAPABILITY_OBSERVATIONS = {
        "claimed": False, "detected": False, "challenge_observed": False, "handshake_succeeded": False, "capability_listed": False,
        "dry_run_succeeded": False, "payment_authorized": False, "payment_accepted": False, "execution_succeeded": False,
        "resource_delivered": False, "receipt_observed": False, "failed": False, "unknown": False,
    }
    flags = dict(DEFAULT_CAPABILITY_OBSERVATIONS)
    flags.update(capability_observations or {})

    if highest_observed_stage == "unknown":
        progression = ["detected", "challenge_observed", "handshake_succeeded", "capability_listed", "dry_run_succeeded", "payment_authorized", "payment_accepted", "execution_succeeded", "resource_delivered", "receipt_observed"]
        for stage in reversed(progression):
            if flags.get(stage):
                highest_observed_stage = stage
                break
    import datetime
    obs_time = last_observed_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": PROTOCOL_ROLES_SCHEMA_VERSION, "role": role, "protocol": protocol, "capability_observations": flags,
        "highest_observed_stage": highest_observed_stage, "last_observed_at": obs_time, "evidence_refs": []
    }

def build_verification_cost_vector(surface_verification: Optional[dict] = None, reporter_identity_verification: Optional[dict] = None, risk: Optional[dict] = None, label: str = "unknown") -> dict:
    def_surface = {"input_tokens": None, "output_tokens": None, "vision_frames": 0, "vision_pixels_total": None, "tool_calls": 0, "http_requests": 0, "browser_steps": 0, "payment_attempts": 0, "retries": 0, "wall_clock_ms": 0}
    def_surface.update(surface_verification or {})
    def_identity = {"performed": False, "method": None, "public_key_type": None, "http_requests": 0, "signature_operations": 0, "llm_tokens": 0, "cached": None}
    def_identity.update(reporter_identity_verification or {})
    def_risk = {"personal_data_required": False, "human_confirmation_required": False, "irreversible_action_attempted": False}
    def_risk.update(risk or {})
    valid_labels = {"low", "medium", "high", "unknown"}
    if label not in valid_labels: label = "unknown"
    return {
        "schema_version": VERIFICATION_COST_VECTOR_SCHEMA_VERSION, "source": "sdk_reported", "not_server_metered": True, "not_a_billing_record": True, "not_a_truth_proof": True,
        "surface_verification": def_surface, "reporter_identity_verification": def_identity, "risk": def_risk,
        "derived": {"formula_version": VERIFICATION_COST_FORMULA_VERSION, "label": label, "score": None}
    }

class DomainObservationSlotResponse(BaseModel):
    request_id: str
    domain: str
    status: str
    requester_paid: bool = True
    domain_owner_verified: bool = False
    sponsor_verified: bool = False
    domain_control_verified: bool = False
    sponsor_verification_status: str = "unverified"
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    sponsor_type: str = "paid_observation_slot"
    duration_days: int = 7
    observation_profile: str = "public_safe_light"
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    status_url: Optional[str] = None
    public_read_model_url: Optional[str] = None
    result_handle: Optional[str] = None
    request_hash: Optional[str] = None
    constraints: Dict[str, Any] = Field(default_factory=dict)

class VerifiedDomainTrackPrice(BaseModel):
    amount: str
    currency: str
    duration_days: int

class VerifiedDomainTrackNextAction(BaseModel):
    action: str
    method: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    description: Optional[str] = None

class VerifiedDomainTrackRegistrationResponse(BaseModel):
    request_id: str
    domain: str
    status: str
    requester_paid: bool = True
    sponsor_type: str = "verified_domain_track"
    track_type: str = "verified_domain_track"
    track_plan: str = "verified_domain_track_lite"
    track_status: str = "pending_verification"
    price: Optional[VerifiedDomainTrackPrice] = None
    duration_days: int = 30
    observation_interval_hours: int = 168
    observation_profile: str = "public_safe_light"
    verification_required: bool = True
    domain_owner_verified: bool = False
    sponsor_verified: bool = False
    domain_control_verified: bool = False
    sponsor_verification_status: str = "unverified"
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    track_expires_at: Optional[str] = None
    sponsor_challenge_url: Optional[str] = None
    status_url: Optional[str] = None
    public_read_model_url: Optional[str] = None
    result_handle: Optional[str] = None
    request_hash: Optional[str] = None
    next_actions: List[VerifiedDomainTrackNextAction] = Field(default_factory=list)
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
    not_a_recommendation: bool = True
    not_a_trust_score: bool = True

class VerifiedDomainTrackReadModel(BaseModel):
    track_type: str
    track_plan: str
    track_status: str
    is_active_verified_track: bool
    request_id: Optional[str] = None
    domain: Optional[str] = None
    track_activated_at: Optional[str] = None
    track_expires_at: Optional[str] = None
    observation_interval_hours: Optional[int] = None
    last_observed_at: Optional[str] = None
    next_observable_at: Optional[str] = None
    observation_count: int = 0
    sponsor_verification_status: str = "unknown"
    domain_control_verified: bool = False
    sponsor_verified: bool = False
    domain_owner_verified: bool = False
    verification_method: Optional[str] = None
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
    not_a_recommendation: bool = True
    not_a_trust_score: bool = True
    domain_owner_verified_semantics: str = "legacy_alias_for_domain_control_verified_not_legal_ownership"
    not_ai_discovery_standard: bool = True
    not_standard_compliance_proof: bool = True
    domain_control_verification: Optional[Dict[str, Any]] = None

class VerifiedDomainTrackSummary(BaseModel):
    has_active_verified_domain_track: bool
    current_track: Optional[VerifiedDomainTrackReadModel] = None
    not_a_verdict: bool = True
    not_a_recommendation: bool = True
    not_a_trust_score: bool = True

class DomainObservationRequestStatus(BaseModel):
    request_id: str
    domain: str
    status: str
    requester_paid: bool = True
    domain_owner_verified: bool = False
    sponsor_verified: bool = False
    domain_control_verified: bool = False
    sponsor_verification_status: str = "unverified"
    verification_method: str = "none"
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    verified_at: Optional[str] = None
    verification_expires_at: Optional[str] = None
    sponsor_verification: Optional["DomainSponsorVerification"] = None
    sponsor_type: str = "paid_observation_slot"
    duration_days: int = 7
    observation_profile: str = "public_safe_light"
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    last_observed_at: Optional[str] = None
    observation_count: int = 0
    public_read_model_url: Optional[str] = None
    not_a_recommendation: bool = True
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
    verified_domain_track: Optional[VerifiedDomainTrackReadModel] = None
    not_a_trust_score: bool = True

class DomainObservationDomainReadModel(BaseModel):
    domain: str
    observation_requests: List[Dict[str, Any]] = Field(default_factory=list)
    sponsor_verification_summary: Optional["DomainSponsorVerificationSummary"] = None
    latest_observations: List[Dict[str, Any]] = Field(default_factory=list)
    discovered_surfaces: List[Dict[str, Any]] = Field(default_factory=list)
    observation_provenance: Dict[str, Any] = Field(default_factory=dict)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    not_a_recommendation: bool = True
    not_legal_ownership_proof: bool = True
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
    verified_domain_track: Optional[VerifiedDomainTrackSummary] = None
    not_a_trust_score: bool = True

class DomainObservationTarget(BaseModel):
    target_id: str
    request_id: str
    domain: str
    seed_urls: List[str] = Field(default_factory=list)
    observation_profile: str = "public_safe_light"
    constraints: Dict[str, Any] = Field(default_factory=dict)
    lease_expires_at: Optional[str] = None

class DomainObservationTargetsResponse(BaseModel):
    targets: List[DomainObservationTarget] = Field(default_factory=list)

class DomainObservationResultSubmission(BaseModel):
    target_id: str
    request_id: str
    observed_domain: str
    observer: Dict[str, Any] = Field(default_factory=lambda: {
        "name": "default_worker",
        "reporter_verification": "self_reported"
    })
    observed_urls: List[Dict[str, Any]] = Field(default_factory=list)
    discovered_surfaces: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    safety_profile: str = "public_safe_light"
    no_payment_to_target: bool = True
    not_a_security_scan: bool = True
    verification_cost_vector: Dict[str, Any] = Field(default_factory=lambda: {
        "http_requests": 0, "tool_calls": 0, "payment_attempts": 0, "personal_data_required": False, "human_confirmation_required": False, "irreversible_action_attempted": False
    })

class DomainObservationResultResponse(BaseModel):
    accepted: bool
    request_id: str
    target_id: str
    observation_id: str
    status: str
    public_read_model_url: Optional[str] = None

class DomainSponsorVerification(BaseModel):
    schema_version: str = "ln_church.domain_sponsor_verification.v1"
    sponsor_verified: bool = False
    domain_owner_verified: bool = False
    domain_control_verified: bool = False
    sponsor_verification_status: str = "unverified"
    verification_method: str = "none"
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    verified_at: Optional[str] = None
    verification_expires_at: Optional[str] = None
    challenge_issued: bool = False
    challenge_present: bool = False
    challenge_expires_at: Optional[str] = None
    not_a_trust_score: bool = True
    not_a_recommendation: bool = True
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
    not_ai_discovery_standard: bool = True
    not_standard_compliance_proof: bool = True

class DomainSponsorChallengeResponse(BaseModel):
    request_id: str
    domain: str
    challenge_id: str
    challenge_url: str
    challenge_document: Dict[str, Any] = Field(default_factory=dict)
    placement_instructions: Dict[str, Any] = Field(default_factory=dict)
    verify_url: Optional[str] = None
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True

class DomainSponsorVerifyResponse(BaseModel):
    request_id: str
    domain: str
    sponsor_verified: bool = False
    domain_owner_verified: bool = False
    domain_control_verified: bool = False
    sponsor_verification_status: str = "unverified"
    verification_method: str = "http_well_known_challenge"
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    verified_at: Optional[str] = None
    verification_expires_at: Optional[str] = None
    verification_proof_id: Optional[str] = None
    public_read_model_url: Optional[str] = None
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
    domain_owner_verified_semantics: str = "legacy_alias_for_domain_control_verified_not_legal_ownership"
    not_ai_discovery_standard: bool = True
    not_standard_compliance_proof: bool = True

class DomainSponsorVerificationSummary(BaseModel):
    schema_version: str = "ln_church.domain_sponsor_verification_summary.v1"
    has_verified_domain_sponsor: bool = False
    active_request_count: int = 0
    verified_request_count: int = 0
    challenge_issued_count: int = 0
    unverified_request_count: int = 0
    latest_verified_at: Optional[str] = None
    verification_methods: List[str] = Field(default_factory=list)
    verification_scope: str = "domain_control_not_legal_ownership"
    not_legal_ownership_proof: bool = True
    not_a_trust_score: bool = True
    not_a_recommendation: bool = True
    not_a_verdict: bool = True
    not_a_security_scan: bool = True
    not_an_endorsement: bool = True
    not_a_certification: bool = True
