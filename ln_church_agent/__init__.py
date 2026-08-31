from .client import (
    Payment402Client,
    LnChurchClient,
    SURFACE_PREFLIGHT_SCHEMA_VERSION,
    validate_public_domain_for_observation
)
from .task_client import AgentTaskClient
from .task_models import (
    AgentTask,
    AgentTaskPage,
    AgentTaskRewardTerms,
    AgentTaskClaim,
    TaskClaimCredential,
    TaskObservedUrlEntry,
    TaskDiscoveredSurfaceEntry,
    TaskObservationErrorEntry,
    TaskVerificationCostVector,
    TaskDomainObservationSubmission,
    TaskDomainObservationResponse,
    AgentTaskCompletionResponse,
    AgentTaskRewardStatus,
    TaskDefinitionReference,
)
from .task_transport import (
    TaskError,
    TaskTransportError,
    TaskAPIError,
    TaskAmbiguousOutcomeError,
)
from .exceptions import (
    PaymentChallengeError,
    PaymentExecutionError,
    NavigationGuardrailError,
    InvoiceParseError,
    CounterpartyTrustError # v1.4+
)
from .models import (
    AssetType, 
    SchemeType,
    OmikujiResponse, 
    AgentIdentity,
    ConfessionResponse,
    HonoResponse,
    CompareResponse,
    AggregateResponse,
    BenchmarkOverviewResponse,
    HateoasErrorResponse,
    MonzenTraceResponse,
    MonzenMetricsResponse,
    MonzenGraphResponse,
    PaymentPolicy,        
    SettlementReceipt,
    ExecutionResult,
    ParsedChallenge,
    ChallengeSource,
    ExecutionContext,
    TrustDecision,
    OutcomeSummary,
    TrustEvidence,
    InteropRunResult,
    ExternalProtocolRunResult,
    CorpusReplayResult,
    InspectResult,           
    X402ExactDiagnosticResult,
    GrantDiagnostics,
    SponsoredAccessEvidence,
    SandboxEvidence,
    SandboxCorpusCandidate,
    PaymentFailureRecord,
    build_observation_provenance,
    build_protocol_role_observation,
    build_verification_cost_vector,
    OBSERVATION_PROVENANCE_SCHEMA_VERSION,
    PROTOCOL_ROLES_SCHEMA_VERSION,
    VERIFICATION_COST_VECTOR_SCHEMA_VERSION,
    VERIFICATION_COST_FORMULA_VERSION,
    READ_MODEL_REVISION,
    DomainObservationSlotResponse,
    DomainObservationRequestStatus,
    DomainObservationDomainReadModel,
    DomainObservationTarget,
    DomainObservationTargetsResponse,
    DomainObservationResultSubmission,
    DomainObservationResultResponse,
    DomainSponsorVerification,
    DomainSponsorVerificationSummary,
    DomainSponsorChallengeResponse,
    DomainSponsorVerifyResponse,
    VerifiedDomainTrackPrice,
    VerifiedDomainTrackNextAction,
    VerifiedDomainTrackRegistrationResponse,
    VerifiedDomainTrackReadModel,
    VerifiedDomainTrackSummary
)
from .crypto.protocols import EVMSigner, LightningProvider 
from .grants import diagnose_grant_token, decode_grant_token

from .evidence import (
    build_sponsored_access_evidence,
    build_sandbox_evidence_from_response,
    build_sandbox_interop_report_payload,
    build_sandbox_corpus_candidate
)

from .failures import (
    build_payment_failure_record,
    build_payment_failure_observation_payload,
    fingerprint_public_challenge_summary,
    detect_public_challenge_changed_fields
)

from .capabilities import get_capability_matrix


# v1.18's Task-v2 surface is lazy so importing the keyless inspect-only MCP
# does not initialize the scheduled worker or its secret-bearing models.  A
# normal explicit import (``from ln_church_agent import AgentTaskV2Client``)
# resolves and caches exactly the requested public symbol.
_V18_LAZY_EXPORTS = {
    "AgentTaskV2Client": ("task_v2_client", "AgentTaskV2Client"),
    "ScheduledTaskClaimCredential": (
        "task_v2_models",
        "ScheduledTaskClaimCredential",
    ),
    "ScheduledTaskReadiness": (
        "task_v2_models",
        "ScheduledTaskReadiness",
    ),
    "ScheduledCompletionReport": (
        "task_v2_models",
        "ScheduledCompletionReport",
    ),
    "ScheduledCompletionReceipt": (
        "task_v2_models",
        "ScheduledCompletionReceipt",
    ),
    "ScheduledRewardStatus": (
        "task_v2_models",
        "ScheduledRewardStatus",
    ),
    "ScheduledCompletionAcknowledgement": (
        "task_v2_models",
        "ScheduledCompletionAcknowledgement",
    ),
    "TaskV2Error": ("task_v2_transport", "TaskV2Error"),
    "TaskV2TransportError": (
        "task_v2_transport",
        "TaskV2TransportError",
    ),
    "TaskV2APIError": ("task_v2_transport", "TaskV2APIError"),
    "ClaimOutcomeUnknownError": (
        "task_v2_transport",
        "ClaimOutcomeUnknownError",
    ),
    "CompletionOutcomeUnknownError": (
        "task_v2_transport",
        "CompletionOutcomeUnknownError",
    ),
    "ScheduledExecutionContext": (
        "scheduled_http_get_batch",
        "ScheduledExecutionContext",
    ),
    "FrozenCompletionReport": (
        "scheduled_http_get_batch",
        "FrozenCompletionReport",
    ),
    "ScheduledExecutionError": (
        "scheduled_http_get_batch",
        "ScheduledExecutionError",
    ),
    "ScheduledHTTPGetBatchExecutor": (
        "scheduled_http_get_batch",
        "ScheduledHTTPGetBatchExecutor",
    ),
    "ScheduledHttpGetBatchExecutor": (
        "scheduled_http_get_batch",
        "ScheduledHttpGetBatchExecutor",
    ),
    "TaskJournal": ("task_journal", "TaskJournal"),
    "JournalError": ("task_journal", "JournalError"),
}


def __getattr__(name):
    target = _V18_LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    from importlib import import_module

    module = import_module(".%s" % target[0], __name__)
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_V18_LAZY_EXPORTS))

# 汎用別名
Http402Client = Payment402Client 

__all__ = [
    "Payment402Client", 
    "LnChurchClient", 
    "AgentTaskClient",
    "Http402Client", 
    "AssetType",
    "SchemeType",
    "OmikujiResponse",
    "AgentIdentity",
    "ConfessionResponse",
    "HonoResponse",
    "CompareResponse",
    "AggregateResponse",
    "BenchmarkOverviewResponse",
    "HateoasErrorResponse",
    "PaymentChallengeError",
    "PaymentExecutionError",
    "NavigationGuardrailError",
    "InvoiceParseError",
    "MonzenTraceResponse",
    "MonzenMetricsResponse",
    "MonzenGraphResponse",
    "PaymentPolicy",      
    "SettlementReceipt",  
    "EVMSigner",          
    "LightningProvider",
    "ExecutionResult",   
    "ParsedChallenge",
    "ChallengeSource",
    "ExecutionContext",
    "TrustDecision",
    "OutcomeSummary",
    "TrustEvidence",
    "InteropRunResult",
    "ExternalProtocolRunResult",
    "CorpusReplayResult",
    "InspectResult",
    "X402ExactDiagnosticResult",
    "GrantDiagnostics",
    "diagnose_grant_token",
    "decode_grant_token",
    "SponsoredAccessEvidence",
    "SandboxEvidence",
    "build_sponsored_access_evidence",
    "build_sandbox_evidence_from_response",
    "build_sandbox_interop_report_payload",
    "SandboxCorpusCandidate",
    "build_sandbox_corpus_candidate",
    "get_capability_matrix",
    "SURFACE_PREFLIGHT_SCHEMA_VERSION",
    "build_observation_provenance",
    "build_protocol_role_observation",
    "build_verification_cost_vector",
    "OBSERVATION_PROVENANCE_SCHEMA_VERSION",
    "PROTOCOL_ROLES_SCHEMA_VERSION",
    "VERIFICATION_COST_VECTOR_SCHEMA_VERSION",
    "VERIFICATION_COST_FORMULA_VERSION",
    "READ_MODEL_REVISION",
    "DomainObservationSlotResponse",
    "DomainObservationRequestStatus",
    "DomainObservationDomainReadModel",
    "DomainObservationTarget",
    "DomainObservationTargetsResponse",
    "DomainObservationResultSubmission",
    "DomainObservationResultResponse",
    "validate_public_domain_for_observation",
    "DomainSponsorVerification",
    "DomainSponsorVerificationSummary",
    "DomainSponsorChallengeResponse",
    "DomainSponsorVerifyResponse",
    "VerifiedDomainTrackPrice",
    "VerifiedDomainTrackNextAction",
    "VerifiedDomainTrackRegistrationResponse",
    "VerifiedDomainTrackReadModel",
    "VerifiedDomainTrackSummary",
    "AgentTask",
    "AgentTaskPage",
    "AgentTaskRewardTerms",
    "AgentTaskClaim",
    "TaskClaimCredential",
    "TaskObservedUrlEntry",
    "TaskDiscoveredSurfaceEntry",
    "TaskObservationErrorEntry",
    "TaskVerificationCostVector",
    "TaskDomainObservationSubmission",
    "TaskDomainObservationResponse",
    "AgentTaskCompletionResponse",
    "AgentTaskRewardStatus",
    "TaskDefinitionReference",
    "TaskError",
    "TaskTransportError",
    "TaskAPIError",
    "TaskAmbiguousOutcomeError",
    "AgentTaskV2Client",
    "ScheduledTaskClaimCredential",
    "ScheduledTaskReadiness",
    "ScheduledCompletionReport",
    "ScheduledCompletionReceipt",
    "ScheduledRewardStatus",
    "ScheduledCompletionAcknowledgement",
    "TaskV2Error",
    "TaskV2TransportError",
    "TaskV2APIError",
    "ClaimOutcomeUnknownError",
    "CompletionOutcomeUnknownError",
    "ScheduledExecutionContext",
    "FrozenCompletionReport",
    "ScheduledExecutionError",
    "ScheduledHTTPGetBatchExecutor",
    "ScheduledHttpGetBatchExecutor",
    "TaskJournal",
    "JournalError",
]
