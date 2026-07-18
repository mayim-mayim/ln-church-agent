# ln_church_agent/client.py
import requests
import httpx
import re
import asyncio
import importlib.metadata
import uuid
import inspect
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode, urljoin
from typing import Optional, Dict, Any, Callable, List, Tuple, Union
import warnings
import base64
import json
import hashlib
import threading
import time
from decimal import Decimal, InvalidOperation
from collections.abc import Mapping

from eth_account import Account
from .models import (
    AssetType, SchemeType, OmikujiResponse, AgentIdentity, ConfessionResponse,
    HonoResponse, CompareResponse, AggregateResponse, BenchmarkOverviewResponse,
    HateoasErrorResponse, MonzenTraceResponse, MonzenMetricsResponse,
    MonzenGraphResponse, PaymentPolicy, SettlementReceipt,
    ParsedChallenge, ExecutionResult,
    ExecutionContext, TrustDecision, OutcomeSummary, TrustEvidence,
    PaymentEvidenceRecord, EvidenceRepository,
    ChallengeSource, AttestationSource, NextAction,
    _ExecutionUnlock, _FundingPolicy, _EntitlementKind, _ExecutionAccessPlan,
    VerifiedDomainTrackRegistrationResponse,
    VerifiedDomainTrackReadModel,
    VerifiedDomainTrackSummary, CanonicalPaymentRequirement
)
from .exceptions import (
    PaymentExecutionError, InvoiceParseError, NavigationGuardrailError,
    CounterpartyTrustError, PaymentChallengeError
)
from .crypto.protocols import EVMSigner, LightningProvider
from .crypto.evm import (
    derive_eip3009_requirement_nonce, get_trusted_eip3009_metadata,
    validate_eip3009_payload, validate_evm_address,
)
from .crypto.lightning import decode_bolt11_payment_metadata
from .payment_contract import (
    PaymentContractError,
    build_canonical_payment_requirement,
    canonical_json,
    canonical_request_target,
    sha256_prefixed,
    verify_canonical_payment_requirement,
    verify_request_binding,
    verify_requirement_expiry,
)
from .receipts import evaluate_payment_receipt
from .redaction import (
    QUERY_REDACTION,
    redact_remote_metadata,
    redact_url_query as _shared_redact_url_query,
    redact_urls_in_text,
)
from .navigation import (
    canonicalize_http_target,
    resolve_host_addresses,
    validate_redirect_target,
)

try:
    from .crypto.protocols import SolanaSigner
except ImportError:
    SolanaSigner = Any

from .challenges import (
    b64url_decode_json, b64url_encode_json, normalize_scheme,
    parse_www_authenticate, parse_legacy_header, parse_challenge_from_response,
    _normalize_network
)

from .evidence import (
    build_sponsored_access_evidence,
    build_sandbox_evidence_from_response,
    merge_sandbox_report_result,
    build_sandbox_interop_report_payload
)

SURFACE_PREFLIGHT_SCHEMA_VERSION = "ln_church.surface_preflight_read_model.v1"
_DOMAIN_OBSERVATION_REQUEST_ID_RE = re.compile(r"^obsreq_[a-f0-9]+$")

def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("ln-church-agent")
    except importlib.metadata.PackageNotFoundError:
        return "1.16.3"

SDK_VERSION = get_sdk_version()
CUSTOM_USER_AGENT = f"ln-church-agent/{get_sdk_version()}"
_ORIGINAL_REQUESTS_REQUEST = requests.request
_X402_CANONICAL_BINDING_EXTENSION = "lnChurchCanonicalBinding"
_CANONICAL_SVM_EXACT_DISABLED_MESSAGE = (
    "Fail-Closed: canonical SVM exact auto-payment is disabled because "
    "recent-blockhash validity cannot be proven to expire at or before "
    "canonical expires_at."
)

def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1]
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
    except Exception:
        return {}

def _b64url_decode(b64_str: str) -> dict:
    return b64url_decode_json(b64_str)

def _b64url_encode(data_dict: dict) -> str:
    return b64url_encode_json(data_dict)


def _idempotency_key_hash(value: str) -> str:
    return sha256_prefixed(
        "ln_church.idempotency_key.v1\x00" + value
    )


def _x402_canonical_binding(requirement: Mapping[str, Any]) -> Dict[str, str]:
    verified = verify_canonical_payment_requirement(requirement)
    return {
        "schemaVersion": "ln_church.x402_canonical_binding.v1",
        "requirementHash": verified["requirement_hash"],
        "expiresAt": verified["expires_at"],
        "idempotencyKeyHash": _idempotency_key_hash(
            verified["idempotency_key"]
        ),
    }


def _bound_x402_extensions(
    raw_extensions: Any, requirement: Mapping[str, Any]
) -> Dict[str, Any]:
    if raw_extensions is None:
        extensions: Dict[str, Any] = {}
    elif isinstance(raw_extensions, Mapping):
        # JSON round-trip prevents a callback-owned nested mapping from being
        # retained after the approval boundary.
        extensions = json.loads(canonical_json(raw_extensions))
    else:
        raise PaymentExecutionError(
            "Fail-Closed: x402 extensions must be an object."
        )
    binding = _x402_canonical_binding(requirement)
    supplied = extensions.get(_X402_CANONICAL_BINDING_EXTENSION)
    if supplied is not None and supplied != binding:
        raise PaymentExecutionError(
            "Fail-Closed: x402 canonical binding extension contradicts approval."
        )
    extensions[_X402_CANONICAL_BINDING_EXTENSION] = binding
    return extensions


def _normalize_scheme(raw_scheme: str) -> str:
    return normalize_scheme(raw_scheme)

def _normalize_secret_name(value: Any) -> str:
    """Normalize an untrusted key without conflating header and payload policy."""
    raw = str(value).strip()
    # Split both ordinary camelCase and acronym boundaries before folding case.
    # This keeps paymentSignature, APIKey, and XInternalSecret in the same
    # credential families as their snake_case and HTTP-header spellings.
    raw = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", raw)
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", raw)
    normalized = re.sub(r"[^a-z0-9]+", "-", raw.lower())
    return normalized.strip("-")


_SECRET_HEADER_EXACT_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "www-authenticate", "api-key", "x-api-key", "private-key",
    "x-private-key", "internal-secret", "x-internal-secret",
    "client-secret", "x-client-secret", "access-token", "x-access-token",
    "refresh-token", "x-refresh-token", "probe-token", "x-probe-token",
    "idempotency-key", "x-ln-result-handle", "x-ln-request-hash",
    "signature", "signature-input", "dpop",
}

_SECRET_PAYLOAD_EXACT_KEYS = {
    "authorization", "proxy-authorization", "www-authenticate",
    "payment-signature", "payment-response", "x-payment", "macaroon",
    "preimage", "private-key", "cookie", "cookies", "raw-cookie",
    "internal-key", "internal-secret", "x-internal-secret", "client-secret",
    "grant-token", "faucet-proof", "api-key", "idempotency-key",
    "payment-auth", "payment-override", "proof", "signature",
    "raw-signature", "token", "proof-id", "reporter-proof-id", "nonce",
    "challenge-id", "access-token", "refresh-token", "probe-token",
    "verify-token", "interop-token", "mandate-token", "shared-payment-token",
    "secret", "password", "credential", "credentials", "bearer", "headers",
    "raw-headers", "payment-authorization", "auth-header",
    "authorization-header",
}

_SAFE_EVIDENCE_KEYS = {
    "authorization-scheme", "payment-required", "payment-performed",
    "payment-receipt-present", "payment-response-present", "payment-intent",
    "payment-method", "verification-status", "evidence-class",
    "proof-reference", "provider-controlled", "selected-requirement-fingerprint",
    "raw-requirement-fingerprint", "challenge-fingerprint",
    "challenge-fingerprint-before", "challenge-fingerprint-after",
    "target-url-hash", "surface-key", "surface-type", "rail", "scheme",
    "network", "asset", "amount", "currency", "draft-shape", "status",
    "status-code", "completion-status", "satisfaction-level", "failure-reason",
    "upgrade-signal", "rubric-version", "taxonomy-version", "payment-hash",
}

# Receipt claims originate in an untrusted HTTP header.  Keep only identifiers
# that are already known from the locally approved canonical requirement, and
# only when the received value exactly matches that known value.  Arbitrary
# decoded receipt JSON must never become persisted/public SDK state.
_PUBLIC_RECEIPT_BINDING_CLAIMS = ("payment_id", "requirement_hash")
_CANONICAL_PROOF_REFERENCE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _normalize_receipt_proof_reference(value: Any) -> Optional[str]:
    """Return only a canonical digest suitable for public receipt state.

    Payment executors still receive and submit their original wire credential.
    This function is intentionally applied only at the receipt-construction
    boundary, after execution, so a preimage, signature, transaction marker, or
    other rail-specific proof can never be retained by the public model.
    """

    if value is None:
        return None
    text_value = str(value)
    if _CANONICAL_PROOF_REFERENCE_RE.fullmatch(text_value) is not None:
        return text_value
    return sha256_prefixed(text_value)


def _is_secret_header_name(name: Any) -> bool:
    """Return whether an HTTP header belongs to a credential-bearing family."""
    normalized = _normalize_secret_name(name)
    compact = normalized.replace("-", "")
    parts = set(normalized.split("-")) if normalized else set()

    if normalized in _SECRET_HEADER_EXACT_NAMES:
        return True
    if compact in {
        "authorization", "proxyauthorization", "cookie", "setcookie",
        "wwwauthenticate", "apikey", "xapikey", "privatekey", "xprivatekey",
        "internalsecret", "xinternalsecret", "clientsecret", "xclientsecret",
        "accesstoken", "xaccesstoken", "refreshtoken", "xrefreshtoken",
        "probetoken", "xprobetoken", "idempotencykey", "xlnresulthandle",
        "xlnrequesthash", "granttoken", "faucetproof", "paymentauthorization",
        "l402credential", "mpptoken", "macaroon", "preimage", "signature",
        "signatureinput", "dpop",
    }:
        return True
    if compact.endswith(("token", "secret", "credential")):
        return True
    if (
        {"api", "key"}.issubset(parts)
        or {"private", "key"}.issubset(parts)
        or {"idempotency", "key"}.issubset(parts)
    ):
        return True
    return bool(parts.intersection({
        "authorization", "cookie", "grant", "faucet", "payment", "l402",
        "mpp", "macaroon", "preimage", "idempotency", "secret", "token",
        "credential", "bearer",
    }))


def _is_secret_payload_key(key: Any) -> bool:
    """Return whether a recursively inspected payload key contains a secret."""
    normalized = _normalize_secret_name(key)
    compact = normalized.replace("-", "")
    if normalized in _SECRET_PAYLOAD_EXACT_KEYS:
        return True
    parts = normalized.split("-") if normalized else []
    part_set = set(parts)
    if any(part in {
        "authorization", "secret", "password", "credential", "credentials",
        "bearer", "macaroon", "preimage",
    }
           for part in normalized.split("-")):
        return True
    if {"api", "key"}.issubset(part_set) or {"private", "key"}.issubset(part_set):
        return True
    if "signature" in part_set and ("payment" in part_set or "raw" in part_set):
        return True
    if "response" in part_set and "payment" in part_set:
        return True
    if compact in {
        "privatekey", "internalkey", "internalsecret", "clientsecret",
        "apikey", "paymentauth", "paymentoverride", "paymentauthorization",
        "authheader", "authorizationheader", "rawheaders", "rawcookie",
        "proofid", "reporterproofid", "rawsignature", "challengeid",
        "accesstoken", "refreshtoken", "probetoken", "granttoken",
        "faucetproof", "interoptoken", "verifytoken", "verificationtoken",
        "idempotencykey", "mandatetoken", "sharedpaymenttoken",
        "privatetoken", "clienttoken",
    }:
        return True
    if compact.endswith(("token", "secret", "credential", "password")):
        return True
    token_prefixes = {
        "access", "refresh", "probe", "grant", "faucet", "private", "client",
        "interop", "verify", "verification", "mandate", "sharedpayment", "auth",
    }
    if "token" in parts and (len(parts) == 1 or any(p in token_prefixes for p in parts)):
        return True
    return False


def _is_secret_evidence_key(key: Any) -> bool:
    """Apply evidence redaction without deleting public hashes or references."""
    normalized = _normalize_secret_name(key)
    if normalized in _SAFE_EVIDENCE_KEYS:
        return False
    if normalized.endswith(("-hash", "-fingerprint", "-present", "-presence", "-reference")):
        return False
    return _is_secret_payload_key(key)


def _is_secret_key(k: str) -> bool:
    """Backward-compatible payload-key predicate used by evidence redaction."""
    return _is_secret_evidence_key(k)


def _strip_sensitive_headers(headers: Optional[dict]) -> dict:
    return {
        key: value for key, value in dict(headers or {}).items()
        if not _is_secret_header_name(key)
    }


def _redact_evidence_url_query(url: Any) -> Any:
    """Redact every query value only at an external Evidence boundary.

    Request transport, canonical binding, and policy checks intentionally use
    the complete wire URL. Evidence retains query key/order structure for
    diagnostics while preventing arbitrary PII or credentials from crossing.
    """
    return _shared_redact_url_query(url)


def _redact_evidence_value(value: Any, *, field_name: Any = None) -> Any:
    """Deep-copy Evidence values while removing secrets and URL queries."""
    if (
        field_name is not None
        and _is_secret_evidence_key(field_name)
        and value is not None
    ):
        return QUERY_REDACTION
    model_fields = getattr(value.__class__, "model_fields", None)
    model_copy = getattr(value, "model_copy", None)
    if isinstance(model_fields, dict) and callable(model_copy):
        return model_copy(
            update={
                name: _redact_evidence_value(
                    getattr(value, name), field_name=name
                )
                for name in model_fields
            }
        )
    if isinstance(value, dict):
        return {
            key: _redact_evidence_value(item, field_name=key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_evidence_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_evidence_value(item) for item in value)
    if isinstance(value, str):
        return redact_urls_in_text(sanitize_error_msg(value))
    return value


def _redact_evidence_record(
    record: PaymentEvidenceRecord,
) -> PaymentEvidenceRecord:
    return _redact_evidence_value(record)


def _redact_evidence_context(
    context: ExecutionContext,
) -> ExecutionContext:
    """Return a public-field-only copy for repository boundaries.

    A Pydantic ``model_copy`` retains PrivateAttrs, which include raw wire URLs
    and idempotency keys.  Reconstructing the declared model creates fresh,
    empty runtime state while preserving repository-relevant public fields.
    """
    public_fields = context.model_dump(
        exclude={"hints", "past_evidence"}
    )
    past_evidence = (
        [
            _redact_evidence_record(record)
            for record in context.past_evidence
        ]
        if context.past_evidence else None
    )
    return ExecutionContext(
        **public_fields,
        hints=redact_remote_metadata(context.hints),
        past_evidence=past_evidence,
    )


class _PinnedHTTPSAdapter(requests.adapters.HTTPAdapter):
    """Connect to a vetted IP while authenticating the original DNS name."""

    def __init__(self, server_hostname: str):
        self._server_hostname = server_hostname
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["server_hostname"] = self._server_hostname
        pool_kwargs["assert_hostname"] = self._server_hostname
        return super().init_poolmanager(
            connections, maxsize, block=block, **pool_kwargs
        )

def _strip_payload_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: _strip_payload_secrets(v) for k, v in obj.items()
            if not _is_secret_payload_key(k)
        }
    if isinstance(obj, list):
        return [_strip_payload_secrets(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_strip_payload_secrets(v) for v in obj)
    return obj


def _strict_netloc_from_url(url: str) -> str:
    """Return case-insensitive host[:explicit-port] for strict policy matching."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return ""
    try:
        port = parsed.port
    except ValueError:
        raise NavigationGuardrailError("Fail-Closed: Target URL has an invalid port.") from None
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    return f"{hostname}:{port}" if port is not None else hostname


def _normalize_policy_netloc(value: Any) -> str:
    raw = str(value).strip()
    if "://" in raw:
        return _strict_netloc_from_url(raw)
    return raw.lower()


def _netloc_is_allowlisted(url: str, allowlist: Any) -> bool:
    target = _strict_netloc_from_url(url)
    return target in {_normalize_policy_netloc(item) for item in (allowlist or [])}


class _PaymentAttemptTracker:
    """Per-call marker; intentionally internal and never serialized."""
    def __init__(self) -> None:
        self.irreversible_attempt_started = False

    def mark_irreversible(self) -> None:
        self.irreversible_attempt_started = True

def sanitize_error_msg(msg: Any) -> str:
    if not isinstance(msg, str):
        msg = str(msg)
    msg = re.sub(r'(macaroon|preimage|signature|token|key|proof|authorization)[:=]\s*["\']?[A-Za-z0-9\-_+/=]+["\']?', r'\1=[REDACTED]', msg, flags=re.IGNORECASE)
    return msg


def _new_sanitized_exception(error_type: type, message: str) -> Exception:
    """Recreate a compatible public exception without retaining its traceback."""
    try:
        return error_type(message)
    except Exception:
        try:
            recreated = Exception.__new__(error_type)
            Exception.__init__(recreated, message)
            return recreated
        except Exception:
            return PaymentExecutionError(message)

def _derive_surface_key(
    target_url: str,
    method: str = "GET",
    rail: str = "unknown",
    network: str = "unknown",
    asset: str = "unknown",
    authorization_scheme: str = "unknown",
    draft_shape: str = "unknown"
) -> str:
    try:
        parsed = urlparse(target_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        volatile_params = {"ts", "timestamp", "time", "nonce", "session", "sid", "token", "signature", "sig", "expires", "exp", "cache", "cache_bust", "cb", "rand", "random"}
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_params = sorted([(k, v) for k, v in query_params if k.lower() not in volatile_params])
        query = urlencode(filtered_params)

        canonical_url = f"{scheme}://{netloc}{path}"
        if query:
            canonical_url += f"?{query}"
    except Exception:
        canonical_url = target_url

    seed = f"{method.upper()}|{canonical_url}|{rail}|{network}|{asset}|{authorization_scheme}|{draft_shape}"
    return hashlib.sha256(seed.encode('utf-8')).hexdigest()[:24]

def validate_public_domain_for_observation(domain: str) -> bool:
    if not domain or not isinstance(domain, str):
        return False
    d = domain.strip().lower()
    if not d or len(d) > 253:
        return False
    if "://" in d or "/" in d or ":" in d:
        return False
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', d):
        return False
    forbidden = [
        r'^localhost$', r'^127\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.', r'^169\.254\.', r'^::1$', r'^fc00::', r'metadata\.google\.internal'
    ]
    for pat in forbidden:
        if re.search(pat, d):
            return False
    return bool(re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', d))

class Payment402Client:
    def __init__(
        self,
        private_key: Optional[str] = None,
        svm_private_key: Optional[str] = None,
        svm_rpc_url: Optional[str] = None,
        ln_api_url: Optional[str] = None,
        ln_api_key: Optional[str] = None,
        ln_provider: str = "lnbits",
        base_url: str = "",
        evm_rpc_url: Optional[str] = None,
        nwc_bridge_url: Optional[str] = None,
        auto_navigate: bool = False,
        max_hops: int = 2,
        allow_unsafe_navigate: bool = False,
        max_payment_retries: int = 2,
        nwc_uri: Optional[str] = None,
        policy: Optional[PaymentPolicy] = None,
        evm_signer: Optional[EVMSigner] = None,
        ln_adapter: Optional[LightningProvider] = None,
        solana_signer: Optional[SolanaSigner] = None,
        trust_evaluators: Optional[List[Callable]] = None,
        evidence_repo: Optional[EvidenceRepository] = None,
        l402_executor: Optional[Any] = None,
        prefer_lightninglabs_l402: bool = False,
        l402_delegate_allowed_hosts: Optional[List[str]] = None,
        allow_legacy_payment_auth_fallback: bool = False,
    ):
        self.private_key = private_key
        self.ln_api_url = ln_api_url
        self.ln_api_key = ln_api_key
        self.ln_provider = ln_provider
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.evm_rpc_url = evm_rpc_url

        self.auto_navigate = auto_navigate
        self.max_hops = max_hops
        self.allow_unsafe_navigate = allow_unsafe_navigate
        self.max_payment_retries = max_payment_retries
        self.policy = policy or PaymentPolicy()
        self.last_receipt: Optional[SettlementReceipt] = None

        self.evm_signer = evm_signer
        if not self.evm_signer and private_key:
            from .crypto.evm import LocalKeyAdapter
            self.evm_signer = LocalKeyAdapter(private_key)

        self.solana_signer = None
        self.svm_signer = None
        self.svm_rpc_url = svm_rpc_url

        if svm_private_key:
            try:
                from .crypto.solana_svm import LocalSvmAdapter
                self.svm_signer = LocalSvmAdapter(svm_private_key, rpc_url=self.svm_rpc_url)
            except ImportError:
                pass

        if private_key:
            try:
                from .crypto.solana import LocalSolanaAdapter
                self.solana_signer = LocalSolanaAdapter(private_key)
            except Exception:
                pass

        self.ln_adapter = ln_adapter
        if not self.ln_adapter:
            if nwc_uri:
                from .adapters.nwc import NWCAdapter
                self.ln_adapter = NWCAdapter(nwc_uri=nwc_uri, bridge_url=nwc_bridge_url)
            elif ln_api_key:
                from .crypto.lightning import LegacyLNAdapter
                self.ln_adapter = LegacyLNAdapter(ln_api_url, ln_api_key, ln_provider)

        self._async_client: Optional[httpx.AsyncClient] = None
        self.trust_evaluators = trust_evaluators or []
        self.evidence_repo = evidence_repo
        self.l402_executor = l402_executor
        self.prefer_lightninglabs_l402 = prefer_lightninglabs_l402
        self.l402_delegate_allowed_hosts = l402_delegate_allowed_hosts or []
        self.allow_legacy_payment_auth_fallback = allow_legacy_payment_auth_fallback
        self._clock = time.time
        self._receipt_signature_verifier = None
        self._receipt_settlement_binding_checker = None
        self._navigation_resolver = lambda host, port: resolve_host_addresses(host, port)

    def _check_local_policy(self, url: str) -> None:
        target_netloc = _strict_netloc_from_url(url)
        if self.policy:
            blocked = {
                _normalize_policy_netloc(item) for item in (self.policy.blocked_hosts or [])
            }
            if target_netloc in blocked:
                raise NavigationGuardrailError(
                    f"Policy Violation: Host '{target_netloc}' is in blocked_hosts."
                )
            if self.policy.allowed_hosts is not None:
                allowed = {
                    _normalize_policy_netloc(item) for item in self.policy.allowed_hosts
                }
                if target_netloc not in allowed:
                    raise NavigationGuardrailError(
                        f"Policy Violation: Host '{target_netloc}' is not in allowed_hosts."
                    )

    @staticmethod
    def _final_wire_url(method: str, url: str, payload: Mapping[str, Any]) -> str:
        """Freeze the URL that the transport will actually send.

        GET payloads are query parameters.  Materializing them before parsing
        or approving a 402 challenge makes ``resource_url`` and the wire target
        one value instead of two late-bound views.
        """
        canonical = canonicalize_http_target(url).url
        prepared = requests.Request(
            method.upper(),
            canonical,
            params=(payload if method.upper() == "GET" and payload else None),
        ).prepare()
        if not isinstance(prepared.url, str):
            raise PaymentExecutionError(
                "Fail-Closed: Unable to materialize final wire URL."
            )
        # requests normalizes percent escapes while preparing (for example
        # %2f -> %2F).  Send and approve this exact prepared representation.
        return canonicalize_http_target(prepared.url).url

    def _compute_fingerprint(
        self, method: str, url: str, original_payload: dict,
        idempotency_key: Optional[str] = None,
    ) -> str:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
        host = parsed.hostname.lower() if parsed.hostname else ""
        canonical_url = f"{parsed.scheme.lower()}://{host}:{port}{parsed.path}"
        if parsed.query:
            q_sorted = sorted(parse_qsl(parsed.query, keep_blank_values=True))
            canonical_url += f"?{urlencode(q_sorted)}"

        safe_payload = _strip_payload_secrets(original_payload) if original_payload else "empty"
        payload_hash = hashlib.sha256(json.dumps(safe_payload, sort_keys=True).encode()).hexdigest()
        operation_key = idempotency_key or ""
        return hashlib.sha256(
            f"{method.upper()}:{canonical_url}:{payload_hash}:{operation_key}".encode()
        ).hexdigest()

    def _logical_and_wire_idempotency_key(
        self,
        context: ExecutionContext,
        url: str,
        supplied_key: Optional[str] = None,
        *,
        initialize: bool = False,
    ) -> Tuple[str, str]:
        """Keep one logical key while deriving a non-forwarded cross-origin key."""
        target = canonicalize_http_target(url)
        self._init_context_state(context)
        with context._payment_state_lock:
            if initialize:
                if not isinstance(supplied_key, str) or not supplied_key.strip():
                    raise PaymentExecutionError(
                        "Fail-Closed: Idempotency-Key must be a non-empty string."
                    )
                context._logical_operation_id = supplied_key
                context._idempotency_key = supplied_key
                context._origin_idempotency_keys = {target.origin: supplied_key}
            elif context._logical_operation_id is None:
                logical = (
                    supplied_key
                    or getattr(context, "_idempotency_key", None)
                    or str(uuid.uuid4())
                )
                context._logical_operation_id = logical
                context._idempotency_key = logical
                context._origin_idempotency_keys[target.origin] = logical

            logical = context._logical_operation_id
            wire = context._origin_idempotency_keys.get(target.origin)
            if wire is None:
                wire = "lnc_" + hashlib.sha256(
                    (
                        "ln_church.origin_idempotency.v1|"
                        + logical
                        + "|"
                        + target.origin
                    ).encode("utf-8")
                ).hexdigest()
                context._origin_idempotency_keys[target.origin] = wire
            return logical, wire

    @staticmethod
    def _extract_idempotency_key(headers: Mapping[str, Any]) -> Tuple[bool, Optional[str]]:
        """Extract one explicit idempotency key without case-split ambiguity."""
        values = [
            value for key, value in headers.items()
            if isinstance(key, str) and key.casefold() == "idempotency-key"
        ]
        if not values:
            return False, None
        if any(
            not isinstance(value, str)
            or not value
            or value != value.strip()
            for value in values
        ):
            raise PaymentExecutionError(
                "Fail-Closed: Idempotency-Key must be a non-empty canonical string."
            )
        if any(value != values[0] for value in values[1:]):
            raise PaymentExecutionError(
                "Fail-Closed: Conflicting duplicate Idempotency-Key headers."
            )
        return True, values[0]

    def _initialize_navigation_state(
        self, context: ExecutionContext, fingerprint: str, url: str
    ) -> None:
        canonical = canonicalize_http_target(url).url
        with context._payment_state_lock:
            context._navigation_states.setdefault(
                fingerprint, {"visited": {canonical}, "hops": 0}
            )

    def _claim_navigation_target(
        self, context: ExecutionContext, fingerprint: str, url: str
    ) -> None:
        canonical = canonicalize_http_target(url).url
        with context._payment_state_lock:
            state = context._navigation_states.setdefault(
                fingerprint, {"visited": set(), "hops": 0}
            )
            if canonical in state["visited"]:
                raise NavigationGuardrailError(
                    "Fail-Closed: Redirect or navigation loop detected."
                )
            if state["hops"] >= self.max_hops:
                raise NavigationGuardrailError(
                    "Fail-Closed: Redirect or navigation hop limit exceeded."
                )
            state["visited"].add(canonical)
            state["hops"] += 1

    def _init_context_state(self, context: ExecutionContext):
        if not hasattr(context, "_payment_states"):
            context._payment_states = {}
            context._payment_state_lock = threading.RLock()
        if not hasattr(context, "_ambiguous_reservations"):
            context._ambiguous_reservations = {}
        if not hasattr(context, "_budget_reservations"):
            context._budget_reservations = {}
        if not hasattr(context, "_known_settled_ambiguities"):
            context._known_settled_ambiguities = set()
        if not hasattr(context, "_payment_identities"):
            context._payment_identities = {}
        if not hasattr(context, "_origin_idempotency_keys"):
            context._origin_idempotency_keys = {}
        if not hasattr(context, "_navigation_states"):
            context._navigation_states = {}
        if not hasattr(context, "_navigation_pins"):
            context._navigation_pins = {}

    def _assert_payment_state_allows_402(self, context: ExecutionContext, fingerprint: str) -> None:
        """Give terminal operation state priority over retry counters and parsing."""
        self._init_context_state(context)
        with context._payment_state_lock:
            state = context._payment_states.get(fingerprint, "not_started")
            if state in {
                "in_progress", "completed", "credential_reused", "ambiguous",
                "settlement_unknown",
            }:
                raise PaymentExecutionError(
                    f"Ambiguous payment error: state is {state}. Irreversible action already attempted."
                )

    def _check_and_set_payment_state(self, context: ExecutionContext, fingerprint: str) -> None:
        self._init_context_state(context)
        with context._payment_state_lock:
            state = context._payment_states.get(fingerprint, "not_started")
            if state in [
                "in_progress", "completed", "credential_reused", "ambiguous",
                "settlement_unknown",
            ]:
                raise PaymentExecutionError(f"Ambiguous payment error: state is {state}. Irreversible action already attempted.")
            context._payment_states[fingerprint] = "in_progress"

    def _update_payment_state(self, context: ExecutionContext, fingerprint: str, state: str) -> None:
        self._init_context_state(context)
        with context._payment_state_lock:
            current = context._payment_states.get(fingerprint, "not_started")
            if current in {
                "completed", "credential_reused", "ambiguous",
                "settlement_unknown", "confirmed_not_paid",
            } and current != state:
                return
            context._payment_states[fingerprint] = state

    def _mark_known_settled_ambiguity(
        self, context: ExecutionContext, fingerprint: str
    ) -> None:
        """Mark paid-but-undelivered recovery without reserving spend twice."""
        self._init_context_state(context)
        with context._payment_state_lock:
            context._known_settled_ambiguities.add(fingerprint)
            context._payment_states[fingerprint] = "ambiguous"

    def _register_payment_identity(
        self, context: ExecutionContext, fingerprint: str, parsed: ParsedChallenge
    ) -> None:
        requirement = getattr(parsed, "_canonical_requirement", None)
        if not isinstance(requirement, Mapping):
            return
        identities = tuple(
            requirement.get(field) for field in ("payment_id", "requirement_hash")
            if isinstance(requirement.get(field), str)
        )
        with context._payment_state_lock:
            # Check the complete set before mutating so a later conflict cannot
            # poison identity recovery with a partially registered challenge.
            if any(
                context._payment_identities.get(value) not in (None, fingerprint)
                for value in identities
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: Payment identity was reused across logical operations."
                )
            for value in identities:
                context._payment_identities[value] = fingerprint

    def get_payment_operation_states(
        self, context: ExecutionContext
    ) -> Dict[str, Dict[str, Any]]:
        """Return payment states without exposing credentials or preimages."""
        self._init_context_state(context)
        with context._payment_state_lock:
            identities_by_fingerprint: Dict[str, List[str]] = {}
            for identity, fingerprint in context._payment_identities.items():
                identities_by_fingerprint.setdefault(fingerprint, []).append(identity)
            return {
                fingerprint: {
                    "state": state,
                    "identities": sorted(identities_by_fingerprint.get(fingerprint, [])),
                    "ambiguous_reservation_usd": str(
                        context._ambiguous_reservations.get(fingerprint, Decimal("0"))
                    ),
                    "ambiguity_kind": (
                        "known_settled_delivery"
                        if fingerprint in context._known_settled_ambiguities
                        else (
                            "settlement_unknown"
                            if state in {"ambiguous", "settlement_unknown"}
                            else None
                        )
                    ),
                }
                for fingerprint, state in context._payment_states.items()
            }

    def resolve_ambiguous_payment(
        self, context: ExecutionContext, operation_or_payment_id: str, outcome: str
    ) -> str:
        """Apply an explicit external recovery result to one ambiguous operation.

        ``outcome`` is either ``confirmed_paid`` or ``confirmed_not_paid``.
        The SDK never infers the latter from a timeout or connection failure.
        """
        state, record = self._resolve_ambiguous_payment_state(
            context, operation_or_payment_id, outcome
        )
        if record is not None:
            self._export_evidence_best_effort(record, context)
        return state

    async def resolve_ambiguous_payment_async(
        self, context: ExecutionContext, operation_or_payment_id: str, outcome: str
    ) -> str:
        """Async repository counterpart of :meth:`resolve_ambiguous_payment`."""
        state, record = self._resolve_ambiguous_payment_state(
            context, operation_or_payment_id, outcome
        )
        if record is not None:
            await self._export_evidence_best_effort_async(record, context)
        return state

    def _resolve_ambiguous_payment_state(
        self, context: ExecutionContext, operation_or_payment_id: str, outcome: str
    ) -> Tuple[str, Optional[PaymentEvidenceRecord]]:
        if outcome not in {"confirmed_paid", "confirmed_not_paid"}:
            raise ValueError(
                "outcome must be confirmed_paid or confirmed_not_paid"
            )
        self._init_context_state(context)
        policy_lock = (
            self.policy._session_spend_lock if self.policy else threading.RLock()
        )
        with policy_lock, context._payment_state_lock:
            fingerprint = context._payment_identities.get(
                operation_or_payment_id, operation_or_payment_id
            )
            local_state = context._payment_states.get(
                fingerprint, "not_started"
            )
            known_settled = fingerprint in context._known_settled_ambiguities
            if known_settled and outcome == "confirmed_not_paid":
                raise PaymentExecutionError(
                    "Known-settled payment cannot be recovered as not paid."
                )
            global_event = self._session_budget_operation_event(
                context, fingerprint
            )

            # The policy journal is authoritative across ExecutionContexts.
            # A stale hydrated context may observe the old reservation, but it
            # cannot apply a second or conflicting terminal transition.
            if global_event is not None and global_event[0] == "confirmed":
                if outcome != "confirmed_paid":
                    raise PaymentExecutionError(
                        "Confirmed payment cannot be recovered as not paid."
                    )
                if local_state in {"ambiguous", "settlement_unknown"} and not known_settled:
                    raise PaymentExecutionError(
                        "Payment ambiguity was already resolved by another context."
                    )
                context._budget_reservations.pop(fingerprint, None)
                context._ambiguous_reservations.pop(fingerprint, None)
                context._known_settled_ambiguities.discard(fingerprint)
                context._payment_states[fingerprint] = "completed"
                return "completed", None
            if global_event is not None and global_event[0] == "released":
                if outcome != "confirmed_not_paid":
                    raise PaymentExecutionError(
                        "Released payment reservation cannot be recovered as paid."
                    )
                if local_state in {"ambiguous", "settlement_unknown"}:
                    raise PaymentExecutionError(
                        "Payment ambiguity was already resolved by another context."
                    )
                context._budget_reservations.pop(fingerprint, None)
                context._ambiguous_reservations.pop(fingerprint, None)
                context._payment_states[fingerprint] = "confirmed_not_paid"
                return "confirmed_not_paid", None

            if local_state not in {"ambiguous", "settlement_unknown"}:
                if (
                    local_state == "completed"
                    and outcome == "confirmed_paid"
                ) or (
                    local_state == "confirmed_not_paid"
                    and outcome == "confirmed_not_paid"
                ):
                    return local_state, None
                raise PaymentExecutionError(
                    "Payment operation is not awaiting ambiguity recovery."
                )
            reservation = Decimal("0")
            if global_event is not None:
                if global_event[0] != "reserved":
                    raise PaymentExecutionError(
                        "Payment operation has conflicting global budget state."
                    )
                reservation = global_event[1]
            else:
                reservation = context._ambiguous_reservations.get(
                    fingerprint, Decimal("0")
                )
            if outcome == "confirmed_paid":
                # A reservation for an unknown wallet outcome becomes actual
                # spend.  Remove only the marker; do not refund the budget.
                context._ambiguous_reservations.pop(fingerprint, None)
                if self.policy and reservation:
                    self.policy._session_reserved_usd = max(
                        0.0,
                        self.policy._session_reserved_usd - float(reservation),
                    )
                    self.policy._session_spent_usd += float(reservation)
                    self.policy._session_ledger_version += 1
                    self.policy._restored_session_reservations.setdefault(
                        context.session_id, {}
                    ).pop(fingerprint, None)
                    self._set_session_budget_operation_event(
                        context, fingerprint, "confirmed", reservation
                    )
                context._known_settled_ambiguities.discard(fingerprint)
                context._payment_states[fingerprint] = "completed"
            else:
                context._budget_reservations.pop(fingerprint, None)
                context._ambiguous_reservations.pop(fingerprint, None)
                if self.policy and reservation:
                    self.policy._session_reserved_usd = max(
                        0.0,
                        self.policy._session_reserved_usd - float(reservation),
                    )
                    self.policy._session_ledger_version += 1
                    self.policy._restored_session_reservations.setdefault(
                        context.session_id, {}
                    ).pop(fingerprint, None)
                    self._set_session_budget_operation_event(
                        context, fingerprint, "released", reservation
                    )
                context._payment_states[fingerprint] = "confirmed_not_paid"
            state = context._payment_states[fingerprint]

        record = None
        if reservation > 0:
            budget_event = (
                "confirmed" if outcome == "confirmed_paid" else "released"
            )
            amount = float(reservation)
            record = PaymentEvidenceRecord(
                session_id=context.session_id,
                correlation_id=context.correlation_id,
                target_url=(
                    "urn:ln-church:payment-operation:" + fingerprint
                ),
                method="RECOVERY",
                error_message=(
                    "ambiguity_resolved_" + outcome
                ),
                session_spend_delta_usd=(
                    amount if budget_event == "confirmed" else 0.0
                ),
                session_budget_event=budget_event,
                session_budget_operation_id=fingerprint,
                session_budget_amount_usd=amount,
                payment_performed=(budget_event == "confirmed"),
            )
        return state, record

    def _bind_known_legacy_challenge_to_request(
        self,
        parsed: ParsedChallenge,
        *,
        request_url: str,
        method: str,
        idempotency_key: str,
    ) -> ParsedChallenge:
        """Upgrade known signed/atomic legacy shapes into the frozen contract.

        Unknown values still remain inspect-only.  This bridge is intentionally
        local: it binds the exact request the client is about to authorize and
        never invents an amount, asset, token, network, decimals, or payee.
        """
        if isinstance(getattr(parsed, "_canonical_requirement", None), Mapping):
            return parsed
        if not isinstance(idempotency_key, str) or not idempotency_key:
            return parsed

        target = canonical_request_target(request_url, method)
        now = int(self._clock())

        if parsed.scheme in {"L402", "MPP", "Payment"}:
            # Preserve every parser fail-closed sentinel.  Canonicalizing from
            # the signed invoice must never erase a contradictory/invalid
            # outer declaration and turn it into an executable challenge.
            try:
                self._validate_lightning_challenge_preflight(parsed)
            except PaymentExecutionError:
                return parsed
            invoice = parsed.parameters.get("invoice")
            if not isinstance(invoice, str):
                return parsed
            try:
                metadata = decode_bolt11_payment_metadata(invoice)
            except ValueError:
                return parsed
            if parsed.scheme == "L402":
                macaroon = parsed.parameters.get("macaroon")
                if (
                    not isinstance(macaroon, str)
                    or macaroon != macaroon.strip()
                    or macaroon.startswith("<")
                    or re.fullmatch(r"[A-Za-z0-9+/_=-]+", macaroon) is None
                ):
                    return parsed
                rail = "l402"
            else:
                rail = "mpp"
            challenge_seed = sha256_prefixed(
                f"{parsed.scheme}|{invoice}|{parsed.raw_header or ''}"
            )[7:]
            fields = {
                "schema_version": "ln_church.canonical_payment_requirement.v1",
                **target,
                "rail": rail,
                "authorization_scheme": parsed.scheme,
                "asset_identifier": "lightning:sats",
                "chain": "bitcoin",
                "network": metadata["network"],
                "decimals": 3,
                "amount_atomic": metadata["amount_atomic"],
                "pay_to": metadata["payee"],
                "expires_at": metadata["expires_at"],
                "challenge_id": "ch_" + challenge_seed[:24],
                "payment_id": metadata["payment_hash"],
                "idempotency_key": idempotency_key,
                "credential_payload_hash": sha256_prefixed(invoice),
            }
            try:
                requirement = build_canonical_payment_requirement(fields)
            except PaymentContractError:
                return parsed
            signer_requirement = getattr(parsed, "_canonical_requirement", None)
            parsed._signer_requirement = signer_requirement
            parsed._canonical_requirement = requirement
            parsed._invoice_msats = int(metadata["amount_atomic"])
            parsed._atomic_amount = metadata["amount_atomic"]
            parsed.network = metadata["network"]
            parsed.asset = "SATS"
            parsed.parameters.update(
                {
                    "challenge_id": requirement["challenge_id"],
                    "payment_id": requirement["payment_id"],
                    "idempotency_key": idempotency_key,
                    "requirement_hash": requirement["requirement_hash"],
                    "_selection_reason": "locally_bound_known_lightning",
                }
            )
            return parsed

        signer_requirement = getattr(parsed, "_canonical_requirement", None)
        if parsed.scheme != "exact" or signer_requirement is None:
            return parsed
        raw_resource = (parsed.parameters or {}).get("_raw_resource")
        if raw_resource is not None and not isinstance(raw_resource, Mapping):
            raise PaymentExecutionError(
                "Fail-Closed: x402 challenge resource must be an object."
            )
        if isinstance(raw_resource, Mapping) and raw_resource.get("method") is not None:
            declared_method = raw_resource.get("method")
            if (
                not isinstance(declared_method, str)
                or declared_method != method.upper()
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: x402 challenge resource.method does not "
                    "match the final wire method."
                )
        if isinstance(raw_resource, Mapping) and raw_resource.get("url") is not None:
            try:
                declared_target = canonical_request_target(
                    raw_resource["url"], method
                )
            except (PaymentContractError, TypeError, ValueError):
                raise PaymentExecutionError(
                    "Fail-Closed: x402 challenge resource.url is invalid."
                ) from None
            for field in (
                "url_scheme", "host", "port", "origin", "method",
                "resource_url",
            ):
                if declared_target[field] != target[field]:
                    raise PaymentExecutionError(
                        "Fail-Closed: x402 challenge resource.url does not "
                        f"match the final wire URL ({field})."
                    )
        try:
            network = str(signer_requirement.network)
            token = str(signer_requirement.token_address_or_mint)
            atomic_amount = str(signer_requirement.atomic_amount)
            decimals = int(signer_requirement.decimals)
            pay_to = str(signer_requirement.pay_to)
            asset = str(signer_requirement.asset)
            if (
                not token
                or not pay_to
                or re.fullmatch(r"[1-9][0-9]*", atomic_amount) is None
            ):
                return parsed
            chain = "eip155" if network.startswith("eip155:") else (
                "solana" if network.startswith("solana:") else ""
            )
            if not chain:
                return parsed
            asset_identifier = f"{network}/token:{token}"
            selected_seed = {
                "scheme": "exact",
                "network": network,
                "asset_identifier": asset_identifier,
                "decimals": decimals,
                "amount_atomic": atomic_amount,
                "pay_to": pay_to,
            }
            selected_hash = sha256_prefixed(canonical_json(selected_seed))
            fields = {
                "schema_version": "ln_church.canonical_payment_requirement.v1",
                **target,
                "rail": "x402",
                "authorization_scheme": "x402",
                "asset_identifier": asset_identifier,
                "chain": chain,
                "network": network,
                "decimals": decimals,
                "amount_atomic": atomic_amount,
                "pay_to": pay_to,
                "expires_at": str(now + 300),
                "challenge_id": "ch_" + selected_hash[7:31],
                "payment_id": "pay_" + selected_hash[7:31],
                "idempotency_key": idempotency_key,
                "credential_payload_hash": selected_hash,
            }
            requirement = build_canonical_payment_requirement(fields)
        except (AttributeError, TypeError, ValueError, PaymentContractError):
            return parsed
        parsed._signer_requirement = signer_requirement
        parsed._canonical_requirement = requirement
        parsed._atomic_amount = atomic_amount
        parsed.parameters.update(
            {
                "challenge_id": requirement["challenge_id"],
                "payment_id": requirement["payment_id"],
                "idempotency_key": idempotency_key,
                "requirement_hash": requirement["requirement_hash"],
                "_selection_reason": "locally_bound_known_exact",
            }
        )
        return parsed

    def _validate_lightning_challenge_preflight(
        self, parsed: ParsedChallenge
    ) -> None:
        """Validate inspect-time Lightning declarations before any wallet call."""
        if parsed.scheme not in {"L402", "MPP", "Payment"}:
            return

        if parsed.scheme == "Payment":
            request_declared = bool(
                getattr(parsed, "request_b64_present", False)
            ) or any(
                isinstance(key, str) and key.casefold() == "request"
                for key in parsed.parameters
            )
            draft_shape = getattr(parsed, "draft_shape", None)
            if request_declared and draft_shape != "payment-auth-draft":
                raise PaymentExecutionError(
                    "Fail-Closed: invalid-payment-auth-request"
                )
            if request_declared and (
                not isinstance(getattr(parsed, "payment_method", None), str)
                or parsed.payment_method.casefold() != "lightning"
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: invalid-payment-auth-request"
                )

        if getattr(parsed, "payment_intent", None) == "session":
            raise PaymentExecutionError(
                "Fail-Closed: mpp_session_not_supported_yet"
            )

        if (
            parsed.scheme == "Payment"
            and getattr(parsed, "draft_shape", None) == "payment-auth-draft"
            and not getattr(self, "allow_legacy_payment_auth_fallback", False)
        ):
            raise PaymentExecutionError(
                "Fail-Closed: unsupported-payment-auth-json"
            )

        inv_msats = getattr(parsed, "_invoice_msats", None)
        if inv_msats == -2:
            raise PaymentExecutionError(
                "Fail-Closed: Mismatch between MPP declared amount and BOLT11 invoice amount."
            )
        if inv_msats == -3:
            raise PaymentExecutionError(
                "Fail-Closed: Unparseable declared amount in request."
            )
        if inv_msats == -4:
            raise PaymentExecutionError(
                "Fail-Closed: Unknown currency or unit declared."
            )
        if not isinstance(inv_msats, int) or isinstance(inv_msats, bool) or inv_msats <= 0:
            raise PaymentExecutionError(
                "Fail-Closed: Invalid, amountless, or negative BOLT11 invoice."
            )

        if parsed.scheme == "L402":
            from .adapters.l402_delegate import _validated_l402_challenge

            _validated_l402_challenge(parsed)

    def _parse_challenge(
        self, response: httpx.Response, expected_asset: str = "USDC",
        expected_chain_id: Optional[str] = None, prefer_svm: bool = False,
        request_url: Optional[str] = None, method: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ParsedChallenge:
        allowed = getattr(self.policy, "allowed_networks", None) if self.policy else None
        prefer_svm_flag = prefer_svm or self.svm_signer is not None
        parsed = parse_challenge_from_response(
            response,
            expected_asset=expected_asset,
            expected_chain_id=expected_chain_id,
            allowed_networks=allowed,
            prefer_svm=prefer_svm_flag,
            now=int(self._clock()),
            request_url=request_url,
            request_method=method,
            request_idempotency_key=idempotency_key,
        )
        if request_url and method and idempotency_key:
            parsed = self._bind_known_legacy_challenge_to_request(
                parsed,
                request_url=request_url,
                method=method,
                idempotency_key=idempotency_key,
            )
        return parsed

    def _parse_www_authenticate(self, auth_header: str, source: ChallengeSource) -> ParsedChallenge:
        return parse_www_authenticate(auth_header, source)

    def _estimate_usd_decimal(self, parsed: ParsedChallenge) -> Decimal:
        canonical = getattr(parsed, "_canonical_requirement", None)
        if isinstance(canonical, Mapping) and canonical.get("schema_version") == "ln_church.canonical_payment_requirement.v1":
            canonical_error = None
            try:
                value = verify_canonical_payment_requirement(canonical)
                atomic_amount = getattr(parsed, "_atomic_amount", None)
                if atomic_amount != value["amount_atomic"]:
                    raise ValueError("canonical atomic amount mismatch")
                human_amount = Decimal(value["amount_atomic"]) / (
                    Decimal(10) ** int(value["decimals"])
                )
                asset_identifier = value["asset_identifier"]
                if asset_identifier == "lightning:sats":
                    canonical_asset = "SATS"
                elif (
                    getattr(parsed, "_signer_requirement", None) is not None
                    and getattr(parsed._signer_requirement, "asset", None)
                    in {"USDC", "JPYC"}
                ):
                    canonical_asset = str(parsed._signer_requirement.asset)
                elif asset_identifier.endswith(":usdc"):
                    canonical_asset = "USDC"
                elif asset_identifier.endswith(":jpyc"):
                    canonical_asset = "JPYC"
                else:
                    raise ValueError("unknown canonical asset identifier")
                if parsed.asset != canonical_asset:
                    raise ValueError("canonical asset mismatch")
            except (PaymentContractError, InvalidOperation, TypeError, ValueError) as caught_error:
                canonical_error = sanitize_error_msg(str(caught_error))
            if canonical_error is not None:
                raise PaymentExecutionError(
                    f"Fail-Closed: Invalid canonical amount for policy evaluation. {canonical_error}"
                ) from None
        elif canonical is not None:
            atomic_amount = getattr(parsed, "_atomic_amount", None)
            canonical_error = None
            try:
                decimals = int(canonical.decimals)
                if isinstance(canonical.decimals, bool) or decimals < 0:
                    raise ValueError("invalid decimals")
                if (
                    not isinstance(canonical.atomic_amount, str)
                    or re.fullmatch(r"[1-9][0-9]*", canonical.atomic_amount) is None
                    or atomic_amount != canonical.atomic_amount
                ):
                    raise ValueError("invalid atomic amount")
                human_amount = Decimal(canonical.atomic_amount) / (
                    Decimal(10) ** decimals
                )
                if Decimal(str(canonical.human_amount_decimal)) != human_amount:
                    raise ValueError("inconsistent human amount")
            except (InvalidOperation, TypeError, ValueError, AttributeError) as caught_error:
                canonical_error = sanitize_error_msg(str(caught_error))
            if canonical_error is not None:
                raise PaymentExecutionError(
                    f"Fail-Closed: Invalid canonical amount for policy evaluation. {canonical_error}"
                ) from None
        elif parsed.scheme == "exact":
            raise PaymentExecutionError(
                "Fail-Closed: Exact challenge has no canonical amount for policy evaluation."
            )
        elif parsed.asset == "SATS" and getattr(parsed, "_invoice_msats", None) is not None:
            invoice_msats = getattr(parsed, "_invoice_msats")
            if isinstance(invoice_msats, int) and invoice_msats > 0:
                human_amount = Decimal(invoice_msats) / Decimal("1000")
            else:
                human_amount = Decimal(str(parsed.amount))
        else:
            human_amount = Decimal(str(parsed.amount))

        if parsed.asset == "USDC":
            return human_amount
        if parsed.asset == "JPYC":
            return human_amount * Decimal("0.0067")
        if parsed.asset == "SATS":
            return human_amount * Decimal("0.00065")
        return Decimal("0")

    def _estimate_usd_value(self, parsed: ParsedChallenge) -> float:
        return float(self._estimate_usd_decimal(parsed))

    def _session_budget_operation_event(
        self, context: ExecutionContext, fingerprint: str
    ) -> Optional[Tuple[str, Decimal]]:
        if not self.policy:
            return None
        event = self.policy._session_budget_operation_journal.get(
            context.session_id, {}
        ).get(fingerprint)
        if event is None:
            return None
        return event[0], Decimal(str(event[1]))

    def _set_session_budget_operation_event(
        self,
        context: ExecutionContext,
        fingerprint: str,
        state: str,
        amount: Decimal,
    ) -> None:
        """Update the policy-owned, operation-keyed budget state.

        Callers hold the policy ledger lock.  The per-operation mutation
        version distinguishes ABA transitions whose final tuple is unchanged.
        """
        if not self.policy:
            return
        self.policy._session_budget_operation_journal.setdefault(
            context.session_id, {}
        )[fingerprint] = (state, float(amount))
        self.policy._session_budget_operation_versions.setdefault(
            context.session_id, {}
        )[fingerprint] = self.policy._session_ledger_version

    def _reserve_session_budget(
        self,
        context: ExecutionContext,
        fingerprint: str,
        approved_usd_value: Any,
    ) -> Decimal:
        """Atomically check and reserve one operation against session budget."""
        if not self.policy:
            return Decimal("0")
        reserve = Decimal(str(approved_usd_value))
        if not reserve.is_finite() or reserve < 0:
            raise PaymentExecutionError(
                "Fail-Closed: Session budget reservation cannot be negative."
            )
        self._init_context_state(context)
        with self.policy._session_spend_lock, context._payment_state_lock:
            global_event = self._session_budget_operation_event(
                context, fingerprint
            )
            existing = context._budget_reservations.get(fingerprint)
            ambiguous = context._ambiguous_reservations.get(fingerprint)
            local_existing = existing if existing is not None else ambiguous
            if global_event is not None:
                global_state, global_amount = global_event
                if global_state == "reserved":
                    if local_existing is not None:
                        if local_existing != global_amount:
                            raise PaymentExecutionError(
                                "Fail-Closed: Conflicting reservation amount for operation."
                            )
                        return local_existing
                    raise PaymentExecutionError(
                        "Ambiguous payment error: operation is already reserved "
                        "in the session ledger."
                    )
                if global_state == "confirmed":
                    raise PaymentExecutionError(
                        "Ambiguous payment error: operation is already confirmed."
                    )
                if global_state == "released" and local_existing is not None:
                    raise PaymentExecutionError(
                        "Fail-Closed: Stale context retains a released reservation."
                    )
            if local_existing is not None:
                return local_existing
            projected = (
                Decimal(str(self.policy._session_spent_usd))
                + Decimal(str(self.policy._session_reserved_usd))
                + reserve
            )
            limit = Decimal(str(self.policy.max_spend_per_session_usd))
            if projected > limit:
                raise PaymentExecutionError(
                    "Policy Violation: Total session spend including reservations "
                    f"({format(projected, 'f')} USD) would exceed limit."
                )
            context._budget_reservations[fingerprint] = reserve
            self.policy._session_reserved_usd += float(reserve)
            self.policy._session_ledger_version += 1
            self.policy._budget_session_id = context.session_id
            self._set_session_budget_operation_event(
                context, fingerprint, "reserved", reserve
            )
            return reserve

    def _confirm_session_budget(
        self, context: ExecutionContext, fingerprint: str
    ) -> Decimal:
        """Commit a reservation without adding it to the ledger twice."""
        if not self.policy:
            return Decimal("0")
        self._init_context_state(context)
        with self.policy._session_spend_lock, context._payment_state_lock:
            local_reserve = context._budget_reservations.pop(fingerprint, None)
            if local_reserve is None:
                local_reserve = context._ambiguous_reservations.pop(
                    fingerprint, Decimal("0")
                )
            global_event = self._session_budget_operation_event(
                context, fingerprint
            )
            if global_event is not None and global_event[0] == "confirmed":
                return Decimal("0")
            if global_event is not None and global_event[0] == "released":
                raise PaymentExecutionError(
                    "Fail-Closed: Released reservation cannot be confirmed."
                )
            if (
                global_event is not None
                and global_event[0] == "reserved"
                and not local_reserve
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: Context does not own the global reservation."
                )
            if (
                global_event is not None
                and local_reserve
                and local_reserve != global_event[1]
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: Local/global reservation amount mismatch."
                )
            reserve = (
                global_event[1]
                if global_event is not None else local_reserve
            )
            if reserve:
                self.policy._session_reserved_usd = max(
                    0.0,
                    self.policy._session_reserved_usd - float(reserve),
                )
                self.policy._session_spent_usd += float(reserve)
                self.policy._session_ledger_version += 1
                self._set_session_budget_operation_event(
                    context, fingerprint, "confirmed", reserve
                )
            self.policy._restored_session_reservations.setdefault(
                context.session_id, {}
            ).pop(fingerprint, None)
            return reserve

    def _release_session_budget(
        self, context: ExecutionContext, fingerprint: str
    ) -> Decimal:
        """Cancel a reservation and return capacity to the shared policy."""
        if not self.policy:
            return Decimal("0")
        self._init_context_state(context)
        with self.policy._session_spend_lock, context._payment_state_lock:
            local_reserve = context._budget_reservations.pop(fingerprint, None)
            if local_reserve is None:
                local_reserve = context._ambiguous_reservations.pop(
                    fingerprint, Decimal("0")
                )
            global_event = self._session_budget_operation_event(
                context, fingerprint
            )
            if global_event is not None and global_event[0] in {
                "confirmed", "released",
            }:
                return Decimal("0")
            if (
                global_event is not None
                and global_event[0] == "reserved"
                and not local_reserve
            ):
                # Cleanup for a failed duplicate operation must not cancel the
                # reservation owned by another ExecutionContext.
                return Decimal("0")
            if (
                global_event is not None
                and local_reserve
                and local_reserve != global_event[1]
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: Local/global reservation amount mismatch."
                )
            reserve = (
                global_event[1]
                if global_event is not None else local_reserve
            )
            if reserve:
                self.policy._session_reserved_usd = max(
                    0.0,
                    self.policy._session_reserved_usd - float(reserve),
                )
                self.policy._session_ledger_version += 1
                self._set_session_budget_operation_event(
                    context, fingerprint, "released", reserve
                )
            self.policy._restored_session_reservations.setdefault(
                context.session_id, {}
            ).pop(fingerprint, None)
            return reserve

    def _mark_session_budget_unknown(
        self, context: ExecutionContext, fingerprint: str
    ) -> Decimal:
        """Retain a reservation while exposing its settlement-unknown state."""
        if not self.policy:
            return Decimal("0")
        self._init_context_state(context)
        with self.policy._session_spend_lock, context._payment_state_lock:
            global_event = self._session_budget_operation_event(
                context, fingerprint
            )
            if global_event is not None and global_event[0] != "reserved":
                return Decimal("0")
            reserve = context._budget_reservations.pop(fingerprint, None)
            if reserve is None:
                reserve = context._ambiguous_reservations.get(
                    fingerprint, Decimal("0")
                )
            elif reserve:
                context._ambiguous_reservations[fingerprint] = reserve
            if not reserve and global_event is not None:
                reserve = global_event[1]
                context._ambiguous_reservations[fingerprint] = reserve
            if reserve:
                self.policy._restored_session_reservations.setdefault(
                    context.session_id, {}
                )[fingerprint] = float(reserve)
                self._set_session_budget_operation_event(
                    context, fingerprint, "reserved", reserve
                )
            return reserve

    def _reserve_ambiguous_spend(
        self,
        context: ExecutionContext,
        fingerprint: str,
        parsed: ParsedChallenge,
        approved_usd_value: Optional[Any] = None,
    ) -> float:
        """Reserve the canonical amount once after an irreversible call loses its result."""
        if not self.policy:
            return 0.0
        reserve = (
            Decimal(str(approved_usd_value))
            if approved_usd_value is not None
            else self._estimate_usd_decimal(parsed)
        )
        if reserve <= 0:
            return 0.0
        self._init_context_state(context)
        with self.policy._session_spend_lock, context._payment_state_lock:
            global_event = self._session_budget_operation_event(
                context, fingerprint
            )
            existing = context._ambiguous_reservations.get(fingerprint)
            if existing is not None:
                if global_event is not None and global_event[0] != "reserved":
                    raise PaymentExecutionError(
                        "Fail-Closed: Ambiguous reservation conflicts with global state."
                    )
                return float(existing)
            pre_reserved = context._budget_reservations.pop(fingerprint, None)
            if pre_reserved is not None:
                context._ambiguous_reservations[fingerprint] = pre_reserved
                self.policy._restored_session_reservations.setdefault(
                    context.session_id, {}
                )[fingerprint] = float(pre_reserved)
                self._set_session_budget_operation_event(
                    context, fingerprint, "reserved", pre_reserved
                )
                return float(pre_reserved)
            if global_event is not None:
                raise PaymentExecutionError(
                    "Ambiguous payment error: operation already has global budget state."
                )
            projected = (
                Decimal(str(self.policy._session_spent_usd))
                + Decimal(str(self.policy._session_reserved_usd))
                + reserve
            )
            if projected > Decimal(str(self.policy.max_spend_per_session_usd)):
                raise PaymentExecutionError(
                    "Policy Violation: Ambiguous reservation exceeds session budget."
                )
            context._ambiguous_reservations[fingerprint] = reserve
            self.policy._session_reserved_usd += float(reserve)
            self.policy._session_ledger_version += 1
            self.policy._budget_session_id = context.session_id
            self.policy._restored_session_reservations.setdefault(
                context.session_id, {}
            )[fingerprint] = float(reserve)
            self._set_session_budget_operation_event(
                context, fingerprint, "reserved", reserve
            )
        return float(reserve)

    def _fold_budget_events(
        self, records: List[PaymentEvidenceRecord]
    ) -> Tuple[float, Dict[str, Tuple[str, Decimal]]]:
        """Fold confirmed spend and unresolved reservations independently.

        Older evidence contains only ``session_spend_delta_usd`` and therefore
        remains a confirmed-spend event.  New journal records are keyed by the
        logical operation fingerprint so repeated exports and later releases
        cannot be counted as separate payments.
        """
        legacy_total = Decimal("0")
        seen_receipts = set()
        journal: Dict[str, Tuple[str, Decimal]] = {}
        for record in sorted(records, key=lambda item: item.timestamp):
            event = record.session_budget_event
            operation_id = record.session_budget_operation_id
            try:
                event_amount = Decimal(str(record.session_budget_amount_usd))
                valid_amount = event_amount.is_finite() and event_amount >= 0
            except (InvalidOperation, TypeError, ValueError):
                event_amount = Decimal("0")
                valid_amount = False
            if (
                event in {"reserved", "confirmed", "released"}
                and isinstance(operation_id, str)
                and operation_id
                and valid_amount
            ):
                previous_state, previous_amount = journal.get(
                    operation_id, ("", Decimal("0"))
                )
                # Confirmation is monotonic.  A later retry may legitimately
                # confirm an operation previously released as not-paid, while
                # a stale release must never erase known confirmed spend.
                if event == "confirmed":
                    journal[operation_id] = (
                        "confirmed",
                        event_amount if event_amount else previous_amount,
                    )
                elif event == "released":
                    if previous_state != "confirmed":
                        journal[operation_id] = (
                            "released",
                            event_amount if event_amount else previous_amount,
                        )
                elif previous_state != "confirmed":
                    journal[operation_id] = ("reserved", event_amount)
                continue

            if record.session_spend_delta_usd is not None:
                try:
                    delta = Decimal(str(record.session_spend_delta_usd))
                except (InvalidOperation, TypeError, ValueError):
                    continue
                if not delta.is_finite() or delta < 0:
                    continue
                receipt_id = None
                if record.receipt_summary and isinstance(record.receipt_summary, dict):
                    receipt_id = record.receipt_summary.get("receipt_id")
                if receipt_id:
                    if receipt_id in seen_receipts:
                        continue
                    seen_receipts.add(receipt_id)
                legacy_total += delta

        return float(legacy_total), journal

    def _merge_restored_session_budget(
        self,
        context: ExecutionContext,
        restored_legacy_confirmed_usd: float,
        restored_journal: Dict[str, Tuple[str, Decimal]],
        start_version: int,
        start_confirmed_usd: float,
        start_journal: Dict[str, Tuple[str, float]],
        start_operation_versions: Dict[str, int],
    ) -> None:
        """Merge Evidence history without conflating spend and reservations."""
        if not self.policy:
            return
        self._init_context_state(context)
        with self.policy._session_spend_lock, context._payment_state_lock:
            if context.session_id in self.policy._restored_session_ids:
                cached = self.policy._session_budget_operation_journal.get(
                    context.session_id, {}
                )
                for operation_id, (state, amount_value) in cached.items():
                    if state != "reserved":
                        continue
                    if context._payment_states.get(operation_id) in {
                        "completed", "confirmed_not_paid",
                    }:
                        continue
                    amount = Decimal(str(amount_value))
                    context._ambiguous_reservations.setdefault(
                        operation_id, amount
                    )
                    context._payment_states.setdefault(
                        operation_id, "settlement_unknown"
                    )
                return
            current_confirmed = Decimal(str(self.policy._session_spent_usd))
            concurrent_mutation = (
                self.policy._session_ledger_version != start_version
            )
            current_journal = dict(
                self.policy._session_budget_operation_journal.get(
                    context.session_id, {}
                )
            )
            current_operation_versions = dict(
                self.policy._session_budget_operation_versions.get(
                    context.session_id, {}
                )
            )
            combined_journal = dict(restored_journal)
            if concurrent_mutation:
                # Live journal changes happened after import began and are the
                # newest view.  Overlay them by operation identity so an event
                # exported during repository I/O is not counted twice when it
                # also appears in the returned evidence snapshot.
                for operation_id, event in current_journal.items():
                    if current_operation_versions.get(operation_id, -1) > (
                        start_operation_versions.get(operation_id, -1)
                    ):
                        state, amount = event
                        combined_journal[operation_id] = (
                            state, Decimal(str(amount))
                        )
                confirmed_delta = max(
                    Decimal("0"),
                    current_confirmed - Decimal(str(start_confirmed_usd)),
                )
                tracked_confirmed_delta = Decimal("0")
                for operation_id, (state, amount_value) in current_journal.items():
                    if state != "confirmed":
                        continue
                    prior_state, prior_amount_value = start_journal.get(
                        operation_id, ("", 0.0)
                    )
                    prior_amount = (
                        Decimal(str(prior_amount_value))
                        if prior_state == "confirmed" else Decimal("0")
                    )
                    tracked_confirmed_delta += max(
                        Decimal("0"),
                        Decimal(str(amount_value)) - prior_amount,
                    )
                untracked_confirmed_delta = max(
                    Decimal("0"),
                    confirmed_delta - tracked_confirmed_delta,
                )
            else:
                untracked_confirmed_delta = Decimal("0")

            merged = (
                Decimal(str(restored_legacy_confirmed_usd))
                + sum(
                    (
                        amount for state, amount in combined_journal.values()
                        if state == "confirmed"
                    ),
                    Decimal("0"),
                )
                + untracked_confirmed_delta
            )
            self.policy._session_spent_usd = float(merged)

            reservations = {
                operation_id: amount
                for operation_id, (state, amount) in combined_journal.items()
                if state == "reserved" and amount > 0
            }
            for operation_id, amount in reservations.items():
                if operation_id in context._budget_reservations:
                    continue
                context._ambiguous_reservations.setdefault(operation_id, amount)
                context._payment_states.setdefault(
                    operation_id, "settlement_unknown"
                )
            self.policy._session_reserved_usd = float(
                sum(reservations.values(), Decimal("0"))
            )
            self.policy._budget_session_id = context.session_id
            self.policy._restored_session_ids.add(context.session_id)
            self.policy._restored_session_reservations[context.session_id] = {
                operation_id: float(amount)
                for operation_id, amount in reservations.items()
            }
            self.policy._session_budget_operation_journal[context.session_id] = {
                operation_id: (state, float(amount))
                for operation_id, (state, amount) in combined_journal.items()
            }
            self.policy._session_ledger_version += 1
            merge_version = self.policy._session_ledger_version
            self.policy._session_budget_operation_versions[context.session_id] = {
                operation_id: max(
                    merge_version,
                    current_operation_versions.get(operation_id, -1),
                )
                for operation_id in combined_journal
            }

    def _restore_session_spend_from_evidence(self, context: ExecutionContext) -> None:
        if (
            not self.policy
            or not self.evidence_repo
            or context.session_budget_restored
            or context._session_budget_restored
        ):
            return
        cached_restore = False
        with self.policy._session_spend_lock:
            if context.session_id in self.policy._restored_session_ids:
                cached_restore = True
            start_version = self.policy._session_ledger_version
            start_confirmed_usd = self.policy._session_spent_usd
            start_journal = dict(
                self.policy._session_budget_operation_journal.get(
                    context.session_id, {}
                )
            )
            start_operation_versions = dict(
                self.policy._session_budget_operation_versions.get(
                    context.session_id, {}
                )
            )
        if cached_restore:
            self._merge_restored_session_budget(
                context, start_confirmed_usd, {}, start_version,
                start_confirmed_usd, start_journal,
                start_operation_versions,
            )
            context.session_budget_restored = True
            context._session_budget_restored = True
            return
        try:
            if hasattr(self.evidence_repo, "import_session_evidence"):
                records = self.evidence_repo.import_session_evidence(
                    _redact_evidence_context(context)
                )
                restored_legacy_usd, journal = (
                    self._fold_budget_events(records)
                    if records else (0.0, {})
                )
                self._merge_restored_session_budget(
                    context,
                    restored_legacy_usd,
                    journal,
                    start_version,
                    start_confirmed_usd,
                    start_journal,
                    start_operation_versions,
                )
        except Exception:
            pass
        finally:
            context.session_budget_restored = True
            context._session_budget_restored = True

    async def _restore_session_spend_from_evidence_async(self, context: ExecutionContext) -> None:
        if (
            not self.policy
            or not self.evidence_repo
            or context.session_budget_restored
            or context._session_budget_restored
        ):
            return
        cached_restore = False
        with self.policy._session_spend_lock:
            if context.session_id in self.policy._restored_session_ids:
                cached_restore = True
            start_version = self.policy._session_ledger_version
            start_confirmed_usd = self.policy._session_spent_usd
            start_journal = dict(
                self.policy._session_budget_operation_journal.get(
                    context.session_id, {}
                )
            )
            start_operation_versions = dict(
                self.policy._session_budget_operation_versions.get(
                    context.session_id, {}
                )
            )
        if cached_restore:
            self._merge_restored_session_budget(
                context, start_confirmed_usd, {}, start_version,
                start_confirmed_usd, start_journal,
                start_operation_versions,
            )
            context.session_budget_restored = True
            context._session_budget_restored = True
            return
        try:
            if hasattr(self.evidence_repo, "import_session_evidence_async"):
                records = await self.evidence_repo.import_session_evidence_async(
                    _redact_evidence_context(context)
                )
            elif hasattr(self.evidence_repo, "import_session_evidence"):
                records = self.evidence_repo.import_session_evidence(
                    _redact_evidence_context(context)
                )
            else:
                records = []
            restored_legacy_usd, journal = (
                self._fold_budget_events(records)
                if records else (0.0, {})
            )
            self._merge_restored_session_budget(
                context,
                restored_legacy_usd,
                journal,
                start_version,
                start_confirmed_usd,
                start_journal,
                start_operation_versions,
            )
        except Exception:
            pass
        finally:
            context.session_budget_restored = True
            context._session_budget_restored = True

    def _import_evidence_best_effort(
        self, url: str, context: ExecutionContext
    ) -> List[PaymentEvidenceRecord]:
        """Load advisory Evidence without making repository health payment-critical."""
        if not self.evidence_repo:
            return []
        try:
            importer = getattr(self.evidence_repo, "import_evidence", None)
            if not callable(importer):
                return []
            records = importer(
                _redact_evidence_url_query(url),
                _redact_evidence_context(context),
            )
            return records or []
        except Exception:
            return []

    async def _import_evidence_best_effort_async(
        self, url: str, context: ExecutionContext
    ) -> List[PaymentEvidenceRecord]:
        """Async counterpart that also supports a synchronous repository."""
        if not self.evidence_repo:
            return []
        try:
            importer = getattr(self.evidence_repo, "import_evidence_async", None)
            if not callable(importer):
                importer = getattr(self.evidence_repo, "import_evidence", None)
            if not callable(importer):
                return []
            records = importer(
                _redact_evidence_url_query(url),
                _redact_evidence_context(context),
            )
            if inspect.isawaitable(records):
                records = await records
            return records or []
        except Exception:
            return []

    def _export_evidence_best_effort(
        self, record: PaymentEvidenceRecord, context: ExecutionContext
    ) -> None:
        """Keep Evidence persistence secondary to the primary payment outcome."""
        if not self.evidence_repo:
            return
        try:
            exporter = getattr(self.evidence_repo, "export_evidence", None)
            if callable(exporter):
                exporter(
                    _redact_evidence_record(record),
                    _redact_evidence_context(context),
                )
        except Exception:
            return

    async def _export_evidence_best_effort_async(
        self, record: PaymentEvidenceRecord, context: ExecutionContext
    ) -> None:
        """Persist Evidence if possible without exposing repository exceptions."""
        if not self.evidence_repo:
            return
        try:
            exporter = getattr(self.evidence_repo, "export_evidence_async", None)
            if not callable(exporter):
                exporter = getattr(self.evidence_repo, "export_evidence", None)
            if not callable(exporter):
                return
            export_result = exporter(
                _redact_evidence_record(record),
                _redact_evidence_context(context),
            )
            if inspect.isawaitable(export_result):
                await export_result
        except Exception:
            return

    def _enforce_policy(
        self, parsed: ParsedChallenge, target_url: str, method: Optional[str] = None,
        require_canonical: bool = False,
    ):
        canonical = getattr(parsed, "_canonical_requirement", None)
        requirement = None
        if not isinstance(canonical, Mapping) and require_canonical:
            raise PaymentExecutionError(
                "Fail-Closed: Executable challenge has no complete canonical payment requirement."
            )
        if isinstance(canonical, Mapping):
            try:
                requirement = verify_request_binding(
                    canonical,
                    request_url=target_url,
                    method=(method or str(canonical.get("method", ""))).upper(),
                )
                verify_requirement_expiry(requirement, now=int(self._clock()))
            except (PaymentContractError, ValueError, TypeError) as exc:
                raise PaymentExecutionError(
                    f"Fail-Closed: Invalid canonical payment requirement. {sanitize_error_msg(str(exc))}"
                ) from None

            expected_scheme = {
                "l402": "L402",
                "x402": "exact",
            }.get(requirement["rail"], requirement["authorization_scheme"])
            if parsed.scheme != expected_scheme:
                raise PaymentExecutionError(
                    "Fail-Closed: Selected payment rail contradicts canonical requirement."
                )
            if parsed.network != requirement["network"]:
                raise PaymentExecutionError(
                    "Fail-Closed: Selected network contradicts canonical requirement."
                )
            if getattr(parsed, "_atomic_amount", None) != requirement["amount_atomic"]:
                raise PaymentExecutionError(
                    "Fail-Closed: Selected amount contradicts canonical requirement."
                )
            parsed._approved_requirement_hash = requirement["requirement_hash"]
            parsed._approved_canonical_snapshot = canonical_json(requirement)

        if not self.policy:
            return requirement["requirement_hash"] if requirement else None

        usd_decimal = self._estimate_usd_decimal(parsed)
        if self.policy.max_spend_per_tx_usd == 0.0 and usd_decimal > 0:
            raise PaymentExecutionError("Policy Violation: Strict 0 USD policy blocks sub-sat invoices.")

        # Local policy (allowed_hosts/blocked_hosts) is checked aggressively in _check_local_policy.

        if parsed.scheme not in self.policy.allowed_schemes:
            raise PaymentExecutionError(f"Policy Violation: Scheme '{parsed.scheme}' is restricted.")
        if parsed.asset not in self.policy.allowed_assets:
            raise PaymentExecutionError(f"Policy Violation: Asset '{parsed.asset}' is restricted.")

        usd_value = float(usd_decimal)
        if usd_decimal > Decimal(str(self.policy.max_spend_per_tx_usd)):
            raise PaymentExecutionError(f"Policy Violation: Amount ({usd_value:.4f} USD) exceeds max_spend_per_tx_usd ({self.policy.max_spend_per_tx_usd}).")
        with self.policy._session_spend_lock:
            projected = (
                Decimal(str(self.policy._session_spent_usd))
                + Decimal(str(self.policy._session_reserved_usd))
                + usd_decimal
            )
            if projected > Decimal(str(self.policy.max_spend_per_session_usd)):
                raise PaymentExecutionError(
                    "Policy Violation: Total session spend including reservations "
                    f"({float(projected):.4f} USD) would exceed limit."
                )

        if getattr(self.policy, "allowed_networks", None) is not None:
            if parsed.network not in self.policy.allowed_networks:
                raise PaymentExecutionError(f"Policy Violation: Network '{parsed.network}' is not in allowed_networks.")

        return requirement["requirement_hash"] if requirement else None

    def _assert_approved_canonical_snapshot_unchanged(
        self,
        parsed: ParsedChallenge,
        *,
        target_url: str,
        method: str,
        expected_snapshot_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        stored_snapshot_json = getattr(parsed, "_approved_canonical_snapshot", None)
        snapshot_json = expected_snapshot_json or stored_snapshot_json
        current = getattr(parsed, "_canonical_requirement", None)
        if not isinstance(snapshot_json, str) or not isinstance(current, Mapping):
            raise PaymentExecutionError(
                "Fail-Closed: Canonical payment requirement was not frozen at policy approval."
            )
        if (
            expected_snapshot_json is not None
            and stored_snapshot_json != expected_snapshot_json
        ):
            raise PaymentExecutionError(
                "Fail-Closed: Canonical approval snapshot changed during signer execution."
            )
        try:
            snapshot = json.loads(snapshot_json)
            requirement = verify_request_binding(
                snapshot, request_url=target_url, method=method
            )
            verify_requirement_expiry(requirement, now=int(self._clock()))
            current_requirement = verify_request_binding(
                current, request_url=target_url, method=method
            )
        except (PaymentContractError, ValueError, TypeError) as exc:
            raise PaymentExecutionError(
                "Fail-Closed: Canonical payment requirement changed after policy approval. "
                + sanitize_error_msg(str(exc))
            ) from None
        if canonical_json(current_requirement) != snapshot_json:
            raise PaymentExecutionError(
                "Fail-Closed: Canonical payment requirement changed after policy approval."
            )
        return requirement

    def _approve_payment_requirement(
        self,
        parsed: ParsedChallenge,
        *,
        target_url: str,
        method: str,
        context: ExecutionContext,
        fingerprint: str,
    ) -> None:
        """Bind policy approval to canonical bytes before state reservation."""
        try:
            self._validate_lightning_challenge_preflight(parsed)
            self._enforce_policy(
                parsed, target_url, method, require_canonical=True
            )

            # A custom signer is application code and may retain a reference to
            # the ParsedChallenge (for example through _last_parsed_challenge).
            # Freeze every exact-payment input as immutable JSON at the policy
            # boundary.  The execution path later rehydrates a private copy and
            # never validates signer output against the callback-mutable model.
            if parsed.scheme == "exact":
                signer_requirement = getattr(parsed, "_signer_requirement", None)
                raw_accepted = (parsed.parameters or {}).get("_raw_accepted")
                if (
                    not isinstance(signer_requirement, CanonicalPaymentRequirement)
                    or not isinstance(raw_accepted, Mapping)
                ):
                    raise PaymentExecutionError(
                        "Fail-Closed: Exact payment has no complete signer snapshot."
                    )
                self._validate_exact_canonical_alignment(
                    parsed, signer_requirement, dict(raw_accepted)
                )
                parsed._approved_signer_snapshot = self._exact_signer_snapshot_json(
                    parsed
                )
            else:
                parsed._approved_signer_snapshot = None

            if getattr(parsed, "_invoice_msats", None) is not None:
                dec_sats = Decimal(str(parsed._invoice_msats)) / Decimal("1000")
                if (
                    self.policy.max_spend_per_tx_usd == 0.0
                    and dec_sats > Decimal("0")
                ):
                    raise PaymentExecutionError(
                        "Policy Violation: Strict 0 USD policy blocks sub-sat invoices."
                    )
            # Registration is an atomic replay boundary, not a parsing aid.
            # Perform it only after canonical validation and policy approval so
            # rejected challenges cannot poison later valid operations.
            self._register_payment_identity(context, fingerprint, parsed)
        except Exception:
            self._update_payment_state(
                context, fingerprint, "validation_failed"
            )
            raise

    def _exact_signer_snapshot_json(self, parsed: ParsedChallenge) -> str:
        """Serialize callback-sensitive exact inputs without sharing references."""
        signer_requirement = getattr(parsed, "_signer_requirement", None)
        if not isinstance(signer_requirement, CanonicalPaymentRequirement):
            raise PaymentExecutionError(
                "Fail-Closed: Exact signer requirement is unavailable."
            )
        parameters = parsed.parameters or {}
        if not isinstance(parameters.get("_raw_accepted"), Mapping):
            raise PaymentExecutionError(
                "Fail-Closed: Exact selected payment option is unavailable."
            )

        snapshot = {
            "signer_requirement": {
                "scheme": str(signer_requirement.scheme),
                "network": str(signer_requirement.network),
                "chain_id": signer_requirement.chain_id,
                "asset": str(signer_requirement.asset),
                "token_address_or_mint": str(
                    signer_requirement.token_address_or_mint
                ),
                "decimals": int(signer_requirement.decimals),
                "atomic_amount": str(signer_requirement.atomic_amount),
                "human_amount_decimal": format(
                    Decimal(str(signer_requirement.human_amount_decimal)), "f"
                ),
                "pay_to": str(signer_requirement.pay_to),
                "source_origin": str(signer_requirement.source_origin),
            },
            "parsed_projection": {
                "scheme": str(parsed.scheme),
                "network": str(parsed.network),
                "asset": str(parsed.asset),
                "amount": parsed.amount,
                "atomic_amount": getattr(parsed, "_atomic_amount", None),
                "parameters": parameters,
            },
        }
        try:
            return json.dumps(
                snapshot,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise PaymentExecutionError(
                "Fail-Closed: Exact signer inputs are not immutable JSON values."
            ) from exc

    def _load_approved_exact_signer_snapshot(
        self,
        parsed: ParsedChallenge,
        *,
        expected_snapshot_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        stored_snapshot_json = getattr(parsed, "_approved_signer_snapshot", None)
        snapshot_json = expected_snapshot_json or stored_snapshot_json
        if not isinstance(snapshot_json, str) or not snapshot_json:
            raise PaymentExecutionError(
                "Fail-Closed: Exact signer inputs were not approved by policy."
            )
        if (
            expected_snapshot_json is not None
            and stored_snapshot_json != expected_snapshot_json
        ):
            raise PaymentExecutionError(
                "Fail-Closed: Exact signer approval snapshot changed during signer execution."
            )
        try:
            snapshot = json.loads(snapshot_json)
            signer_fields = snapshot["signer_requirement"]
            projection = snapshot["parsed_projection"]
            if (
                not isinstance(snapshot, dict)
                or not isinstance(signer_fields, dict)
                or not isinstance(projection, dict)
                or not isinstance(projection.get("parameters"), dict)
                or not isinstance(
                    projection["parameters"].get("_raw_accepted"), dict
                )
            ):
                raise ValueError("invalid exact signer snapshot shape")
            CanonicalPaymentRequirement(**signer_fields)
        except (KeyError, TypeError, ValueError) as exc:
            raise PaymentExecutionError(
                "Fail-Closed: Approved exact signer snapshot is invalid."
            ) from exc
        return snapshot

    def _assert_approved_exact_signer_snapshot_unchanged(
        self,
        parsed: ParsedChallenge,
        *,
        target_url: Optional[str] = None,
        method: Optional[str] = None,
        expected_snapshot_json: Optional[str] = None,
        expected_canonical_snapshot_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        if target_url is not None and method is not None:
            self._assert_approved_canonical_snapshot_unchanged(
                parsed,
                target_url=target_url,
                method=method,
                expected_snapshot_json=expected_canonical_snapshot_json,
            )
        snapshot = self._load_approved_exact_signer_snapshot(
            parsed, expected_snapshot_json=expected_snapshot_json
        )
        current = self._exact_signer_snapshot_json(parsed)
        anchor = expected_snapshot_json or parsed._approved_signer_snapshot
        if current != anchor:
            raise PaymentExecutionError(
                "Fail-Closed: Exact signer inputs changed after policy approval."
            )
        return snapshot

    def _recheck_policy_binding_before_payment(
        self, parsed: ParsedChallenge, *, target_url: str, method: str
    ) -> Dict[str, Any]:
        canonical = getattr(parsed, "_canonical_requirement", None)
        approved_hash = getattr(parsed, "_approved_requirement_hash", None)
        if not isinstance(canonical, Mapping) or not isinstance(approved_hash, str):
            raise PaymentExecutionError(
                "Fail-Closed: Payment requirement was not approved by policy."
            )
        try:
            requirement = self._assert_approved_canonical_snapshot_unchanged(
                parsed, target_url=target_url, method=method
            )
        except PaymentExecutionError as exc:
            raise PaymentExecutionError(
                f"Fail-Closed: Canonical payment requirement changed after policy approval. {sanitize_error_msg(str(exc))}"
            ) from None
        if requirement["requirement_hash"] != approved_hash:
            raise PaymentExecutionError(
                "Fail-Closed: Canonical payment requirement changed after policy approval."
            )
        if getattr(parsed, "_atomic_amount", None) != requirement["amount_atomic"]:
            raise PaymentExecutionError(
                "Fail-Closed: Canonical amount changed after policy approval."
            )
        if requirement["rail"] in {"l402", "mpp"}:
            invoice = parsed.parameters.get("invoice")
            if (
                not isinstance(invoice, str)
                or sha256_prefixed(invoice) != requirement["credential_payload_hash"]
            ):
                raise PaymentExecutionError(
                    "Fail-Closed: Lightning credential payload changed after policy approval."
                )
        elif requirement["rail"] == "x402":
            snapshot = self._assert_approved_exact_signer_snapshot_unchanged(parsed)
            signer_requirement = snapshot["signer_requirement"]
            try:
                selected_seed = {
                    "scheme": "exact",
                    "network": str(signer_requirement["network"]),
                    "asset_identifier": requirement["asset_identifier"],
                    "decimals": int(signer_requirement["decimals"]),
                    "amount_atomic": str(signer_requirement["atomic_amount"]),
                    "pay_to": str(signer_requirement["pay_to"]),
                }
                signer_hash = sha256_prefixed(canonical_json(selected_seed))
            except (KeyError, TypeError, ValueError, PaymentContractError):
                signer_hash = None
            if signer_hash != requirement["credential_payload_hash"]:
                raise PaymentExecutionError(
                    "Fail-Closed: Signer payload changed after policy approval."
                )
        return requirement

    def _record_session_spend(
        self,
        parsed: ParsedChallenge,
        l402_report: Optional[Any] = None,
        approved_usd_value: Optional[Any] = None,
    ):
        if not self.policy:
            return
        if l402_report and not getattr(l402_report, "payment_performed", True):
            return
        spend = (
            float(Decimal(str(approved_usd_value)))
            if approved_usd_value is not None
            else self._estimate_usd_value(parsed)
        )
        with self.policy._session_spend_lock:
            self.policy._session_spent_usd += spend

    def _capture_approved_receipt_snapshot(
        self, parsed: ParsedChallenge
    ) -> Dict[str, Any]:
        canonical_snapshot_json = getattr(
            parsed, "_approved_canonical_snapshot", None
        )
        if not isinstance(canonical_snapshot_json, str):
            raise PaymentExecutionError(
                "Fail-Closed: Receipt metadata has no approved canonical snapshot."
            )
        return {
            "canonical_snapshot_json": canonical_snapshot_json,
            "scheme": str(parsed.scheme),
            "network": str(parsed.network),
            "asset": str(parsed.asset),
            "amount": parsed.amount,
            "atomic_amount": getattr(parsed, "_atomic_amount", None),
            "usd_value": str(self._estimate_usd_decimal(parsed)),
        }

    def _preflight_approved_payment_before_session_budget(
        self,
        parsed: ParsedChallenge,
        approved_snapshot: Mapping[str, Any],
        *,
        target_url: str,
        method: str,
    ) -> Dict[str, Any]:
        """Reject non-executable canonical lanes before budget reservation.

        This boundary reads only the already-approved canonical snapshot and
        its public ParsedChallenge projection.  It must not inspect payment
        credentials, signer configuration, fee-payer data, wallets, or RPC.
        """
        requirement = self._assert_approved_receipt_snapshot_unchanged(
            parsed,
            approved_snapshot,
            target_url=target_url,
            method=method,
        )
        if (
            approved_snapshot.get("scheme") == "exact"
            and requirement["rail"] == "x402"
            and str(requirement["network"]).startswith("solana:")
        ):
            raise PaymentExecutionError(
                _CANONICAL_SVM_EXACT_DISABLED_MESSAGE
            )
        return requirement

    def _assert_approved_receipt_snapshot_unchanged(
        self,
        parsed: ParsedChallenge,
        snapshot: Mapping[str, Any],
        *,
        target_url: str,
        method: str,
    ) -> Dict[str, Any]:
        requirement = self._assert_approved_canonical_snapshot_unchanged(
            parsed,
            target_url=target_url,
            method=method,
            expected_snapshot_json=str(snapshot["canonical_snapshot_json"]),
        )
        current_projection = {
            "scheme": str(parsed.scheme),
            "network": str(parsed.network),
            "asset": str(parsed.asset),
            "amount": parsed.amount,
            "atomic_amount": getattr(parsed, "_atomic_amount", None),
        }
        expected_projection = {
            key: snapshot[key]
            for key in (
                "scheme", "network", "asset", "amount", "atomic_amount"
            )
        }
        if current_projection != expected_projection:
            raise PaymentExecutionError(
                "Fail-Closed: Receipt metadata changed during payment execution."
            )
        return requirement

    def _new_settlement_receipt(
        self,
        parsed: ParsedChallenge,
        network_name: str,
        proof_ref: Any,
        l402_report: Optional[Any],
        endpoint: str,
        operation_fingerprint: str = "",
        approved_snapshot: Optional[Mapping[str, Any]] = None,
        payment_performed: Optional[bool] = None,
    ) -> SettlementReceipt:
        if approved_snapshot is not None:
            requirement = json.loads(
                str(approved_snapshot["canonical_snapshot_json"])
            )
            receipt_scheme = str(approved_snapshot["scheme"])
            receipt_asset = str(approved_snapshot["asset"])
            receipt_amount = approved_snapshot["amount"]
        else:
            requirement = getattr(parsed, "_canonical_requirement", None) or {}
            receipt_scheme = parsed.scheme
            receipt_asset = parsed.asset
            receipt_amount = parsed.amount
        payment_id = requirement.get("payment_id") if isinstance(requirement, Mapping) else None
        requirement_hash = requirement.get("requirement_hash") if isinstance(requirement, Mapping) else None
        idempotency_key = requirement.get("idempotency_key") if isinstance(requirement, Mapping) else None
        normalized_proof_ref = _normalize_receipt_proof_reference(proof_ref)
        receipt_identity = {
            "schema_version": "ln_church.receipt_identity.v1",
            "operation_fingerprint": operation_fingerprint,
            "idempotency_key_hash": (
                _idempotency_key_hash(idempotency_key)
                if isinstance(idempotency_key, str) and idempotency_key
                else ""
            ),
            "requirement_hash": requirement_hash or "",
            "proof_reference": normalized_proof_ref or "",
        }
        receipt_id = "rcpt_" + hashlib.sha256(
            canonical_json(receipt_identity).encode("utf-8")
        ).hexdigest()
        settlement_verified = bool(
            receipt_scheme == "L402"
            and payment_id
            and getattr(l402_report, "payment_hash", None) == payment_id
        )
        performed = (
            bool(payment_performed)
            if payment_performed is not None
            else (
                getattr(l402_report, "payment_performed", True)
                if l402_report
                else True
            )
        )
        return SettlementReceipt(
            receipt_id=receipt_id,
            scheme=receipt_scheme,
            network=network_name,
            asset=receipt_asset,
            settled_amount=receipt_amount,
            proof_reference=normalized_proof_ref,
            verification_status=(
                "settlement_verified" if settlement_verified else "unverified"
            ),
            settlement_verified=settlement_verified,
            payment_id=payment_id,
            requirement_hash=requirement_hash,
            delegate_source=getattr(l402_report, "delegate_source", "native") if l402_report else "native",
            payment_hash=getattr(l402_report, "payment_hash", None) if l402_report else None,
            fee_sats=getattr(l402_report, "fee_sats", None) if l402_report else None,
            cached_token_used=getattr(l402_report, "cached_token_used", False) if l402_report else False,
            payment_performed=performed,
            endpoint=endpoint,
        )

    def _apply_server_receipt_state(
        self, receipt: Optional[SettlementReceipt], headers: Mapping[str, Any], status_code: int
    ) -> None:
        if receipt is None:
            return

        def settlement_binding(claims: Mapping[str, Any]) -> bool:
            if (
                claims.get("payment_id") != receipt.payment_id
                or claims.get("requirement_hash") != receipt.requirement_hash
            ):
                return False
            checker = self._receipt_settlement_binding_checker
            # Identity equality is necessary but not settlement evidence.  A
            # configured checker must independently establish the settlement.
            return checker is not None and checker(claims) is True

        state = evaluate_payment_receipt(
            headers,
            status_code,
            signature_verifier=self._receipt_signature_verifier,
            settlement_binding_checker=settlement_binding,
        )
        receipt.present = state.present
        receipt.server_asserted = state.server_asserted
        receipt.signature_verified = state.signature_verified
        # A locally verified preimage remains settlement evidence even when the
        # HTTP receipt is merely unsigned.  A signed receipt can additionally
        # establish the same state through the bound claims path.
        receipt.settlement_verified = receipt.settlement_verified or state.settlement_verified
        receipt.delivered = state.delivered
        receipt.receipt_format = state.format
        receipt.receipt_error = state.error
        receipt.receipt_token_hash = (
            sha256_prefixed(state.token) if state.token is not None else None
        )
        public_claims: Dict[str, str] = {}
        if isinstance(state.claims, Mapping):
            expected_claims = {
                "payment_id": receipt.payment_id,
                "requirement_hash": receipt.requirement_hash,
            }
            for claim_name in _PUBLIC_RECEIPT_BINDING_CLAIMS:
                expected = expected_claims[claim_name]
                if (
                    isinstance(expected, str)
                    and state.claims.get(claim_name) == expected
                ):
                    # Persist the already-known local value, not the untrusted
                    # object supplied by the receipt.
                    public_claims[claim_name] = expected
        receipt.receipt_claims = public_claims or None
        if state.signature_verified:
            receipt.source = AttestationSource.SERVER_JWS
        elif state.server_asserted:
            receipt.source = AttestationSource.UNSIGNED_SERVER
        if receipt.settlement_verified:
            receipt.verification_status = "settlement_verified"
        elif state.signature_verified:
            receipt.verification_status = "signature_verified"
        elif state.server_asserted:
            receipt.verification_status = "server_asserted"
        else:
            receipt.verification_status = "unverified"

    def _validate_exact_canonical_alignment(
        self, parsed: ParsedChallenge, canonical: CanonicalPaymentRequirement,
        raw_accepted: dict,
    ) -> None:
        """Reject every retained exact-challenge projection that contradicts canonical."""
        mismatches = []
        params = parsed.parameters or {}

        def compare_network(value: Any, field: str) -> None:
            if value not in (None, "") and _normalize_network(str(value)) != canonical.network:
                mismatches.append(field)

        def compare_chain(value: Any, field: str) -> None:
            if value in (None, "") or canonical.chain_id is None:
                return
            try:
                if int(value) != canonical.chain_id:
                    mismatches.append(field)
            except (TypeError, ValueError):
                mismatches.append(field)

        def compare_asset(value: Any, field: str) -> None:
            if value in (None, ""):
                return
            normalized = str(value)
            if normalized.startswith("0x") or canonical.network.startswith("solana:"):
                if normalized.lower() != canonical.token_address_or_mint.lower():
                    mismatches.append(field)
            elif normalized.upper() != canonical.asset.upper():
                mismatches.append(field)

        def compare_atomic(value: Any, field: str) -> None:
            if value not in (None, "") and str(value) != canonical.atomic_amount:
                mismatches.append(field)

        def compare_destination(value: Any, field: str) -> None:
            if value not in (None, "") and str(value).lower() != canonical.pay_to.lower():
                mismatches.append(field)

        if parsed.scheme != canonical.scheme or canonical.scheme != "exact":
            mismatches.append("scheme")
        compare_network(parsed.network, "parsed.network")
        compare_network(params.get("network"), "parameters.network")
        if parsed.asset != canonical.asset:
            mismatches.append("parsed.asset")
        compare_asset(params.get("token_address"), "parameters.token_address")
        compare_atomic(params.get("atomic_amount"), "parameters.atomic_amount")
        compare_atomic(params.get("_raw_amount"), "parameters.raw_amount")
        compare_destination(params.get("destination"), "parameters.destination")
        compare_destination(params.get("payTo"), "parameters.payTo")
        compare_chain(params.get("chainId") or params.get("chain_id"), "parameters.chainId")

        compare_network(params.get("_raw_outer_network"), "outer.network")
        compare_chain(params.get("_raw_outer_chain_id"), "outer.chainId")
        compare_chain(params.get("_raw_outer_chain_id_alias"), "outer.chain_id")
        compare_asset(params.get("_raw_outer_asset"), "outer.asset")
        compare_asset(params.get("_raw_outer_contract"), "outer.contract")
        compare_asset(params.get("_raw_outer_token_address"), "outer.token_address")
        compare_atomic(params.get("_raw_outer_amount"), "outer.amount")
        compare_destination(params.get("_raw_outer_destination"), "outer.destination")
        compare_destination(params.get("_raw_outer_pay_to"), "outer.payTo")

        outer_parameters = params.get("_raw_outer_parameters")
        if isinstance(outer_parameters, dict):
            compare_network(outer_parameters.get("network"), "outer.parameters.network")
            compare_chain(outer_parameters.get("chainId"), "outer.parameters.chainId")
            compare_chain(outer_parameters.get("chain_id"), "outer.parameters.chain_id")
            compare_asset(outer_parameters.get("asset"), "outer.parameters.asset")
            compare_asset(outer_parameters.get("contract"), "outer.parameters.contract")
            compare_asset(
                outer_parameters.get("token_address"),
                "outer.parameters.token_address",
            )
            compare_atomic(outer_parameters.get("amount"), "outer.parameters.amount")
            compare_destination(outer_parameters.get("payTo"), "outer.parameters.payTo")
            compare_destination(
                outer_parameters.get("destination"), "outer.parameters.destination"
            )

        compare_network(raw_accepted.get("network"), "accepted.network")
        compare_chain(raw_accepted.get("chainId"), "accepted.chainId")
        compare_chain(raw_accepted.get("chain_id"), "accepted.chain_id")
        if raw_accepted.get("scheme", "exact") != canonical.scheme:
            mismatches.append("accepted.scheme")
        compare_asset(raw_accepted.get("asset"), "accepted.asset")
        compare_asset(raw_accepted.get("contract"), "accepted.contract")
        compare_asset(raw_accepted.get("token_address"), "accepted.token_address")
        compare_atomic(raw_accepted.get("amount"), "accepted.amount")
        compare_destination(raw_accepted.get("payTo"), "accepted.payTo")
        compare_destination(raw_accepted.get("destination"), "accepted.destination")

        nested = raw_accepted.get("parameters")
        if isinstance(nested, dict):
            compare_network(nested.get("network"), "accepted.parameters.network")
            compare_chain(nested.get("chainId"), "accepted.parameters.chainId")
            compare_chain(nested.get("chain_id"), "accepted.parameters.chain_id")
            compare_asset(nested.get("asset"), "accepted.parameters.asset")
            compare_asset(nested.get("contract"), "accepted.parameters.contract")
            compare_asset(
                nested.get("token_address"), "accepted.parameters.token_address"
            )
            compare_atomic(nested.get("amount"), "accepted.parameters.amount")
            compare_destination(nested.get("payTo"), "accepted.parameters.payTo")
            compare_destination(
                nested.get("destination"), "accepted.parameters.destination"
            )

        if mismatches:
            raise PaymentExecutionError(
                "Fail-Closed: Exact challenge contradicts its canonical requirement: "
                + ", ".join(sorted(set(mismatches)))
            )

    def execute_paid_action(self, *args, **kwargs) -> dict:
        warnings.warn("execute_paid_action() is deprecated. Use execute_request() or execute_detailed() instead.", DeprecationWarning, stacklevel=2)
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            endpoint_path = args[0]
            payload = args[1]
            headers = args[2] if len(args) > 2 else kwargs.get("headers")
            return self.execute_request("POST", endpoint_path, payload, headers)

        method = args[0] if len(args) > 0 else kwargs.get("method", "POST")
        endpoint_path = args[1] if len(args) > 1 else kwargs.get("endpoint_path")
        payload = args[2] if len(args) > 2 else kwargs.get("payload")
        headers = args[3] if len(args) > 3 else kwargs.get("headers")
        return self.execute_request(method, endpoint_path, payload, headers)

    def _process_payment(
        self, parsed: ParsedChallenge, headers: dict, payload: dict,
        method: str = "POST", url: str = "",
        _attempt_tracker: Optional[_PaymentAttemptTracker] = None,
    ) -> Tuple[str, str, Optional[Any]]:
        attempt_tracker = _attempt_tracker or _PaymentAttemptTracker()
        if parsed.scheme == "batch-settlement":
            raise PaymentExecutionError("batch_settlement_execution_not_supported: SDK will not execute deferred batch settlement.")

        if parsed.scheme == "auth-capture":
            raise PaymentExecutionError("auth_capture_execution_not_supported: SDK will not execute auth-capture.")

        canonical_v1 = None
        approved_exact_snapshot = None
        approved_exact_snapshot_json = None
        approved_canonical_snapshot_json = None
        if getattr(parsed, "_approved_requirement_hash", None):
            canonical_v1 = self._recheck_policy_binding_before_payment(
                parsed, target_url=url, method=method.upper()
            )
            approved_canonical_snapshot_json = canonical_json(canonical_v1)
            if canonical_v1["rail"] == "x402":
                approved_exact_snapshot_json = getattr(
                    parsed, "_approved_signer_snapshot", None
                )
                approved_exact_snapshot = (
                    self._assert_approved_exact_signer_snapshot_unchanged(
                        parsed,
                        target_url=url,
                        method=method.upper(),
                        expected_snapshot_json=approved_exact_snapshot_json,
                        expected_canonical_snapshot_json=(
                            approved_canonical_snapshot_json
                        ),
                    )
                )
            idempotency_values = [
                str(value)
                for key, value in headers.items()
                if str(key).lower() == "idempotency-key"
            ]
            if idempotency_values != [canonical_v1["idempotency_key"]]:
                raise PaymentExecutionError(
                    "Fail-Closed: Outgoing idempotency key contradicts canonical requirement."
                )
            if canonical_v1["rail"] not in {"l402", "mpp", "x402"}:
                raise PaymentExecutionError(
                    "Fail-Closed: Canonical rail is inspect-only in this execution path."
                )

        proof_ref = ""
        network_name = parsed.network or "UNKNOWN"
        l402_report = None

        if parsed.scheme in [SchemeType.x402.value, SchemeType.lnc_evm_relay.value, SchemeType.lnc_evm_transfer.value, "exact"]:
            credential_parameters = parsed.parameters or {}
            if approved_exact_snapshot is not None:
                credential_parameters = approved_exact_snapshot[
                    "parsed_projection"
                ]["parameters"]
                canonical_req = CanonicalPaymentRequirement(
                    **approved_exact_snapshot["signer_requirement"]
                )
            else:
                canonical_req = (
                    getattr(parsed, "_signer_requirement", None)
                    or getattr(parsed, "_canonical_requirement", None)
                )

            is_svm_exact = (
                parsed.scheme == "exact"
                and canonical_req is not None
                and str(canonical_req.network).startswith("solana:")
            )

            reason = credential_parameters.get("_selection_reason")
            if reason in [
                "unknown_token_contract", "no_allowed_network_match",
                "outer_inner_mismatch", "invalid_atomic_amount", "invalid_network",
            ]:
                raise PaymentExecutionError(f"Fail-Closed: {reason}")

            if is_svm_exact:
                # A standard x402 SVM transaction is bounded by a recent
                # blockhash's last-valid block height.  The canonical
                # requirement, however, expires at an absolute Unix time.
                # Slot duration is not a protocol constant, so no production
                # check can prove that the block-height lifetime ends at or
                # before that wall-clock deadline.  Adding another Memo is
                # also not an option: the exact-SVM scheme permits exactly one
                # client Memo and reserves it for extra.memo (or a nonce).
                # Halt before inspecting signer or fee-payer credentials so
                # their presence cannot imply that this lane is executable.
                raise PaymentExecutionError(
                    _CANONICAL_SVM_EXACT_DISABLED_MESSAGE
                )

            raw_accepted = credential_parameters.get("_raw_accepted") or {}
            extra = raw_accepted.get("extra") or {}

            if not canonical_req:
                if parsed.scheme == "exact":
                    raise PaymentExecutionError(
                        "Fail-Closed: Exact challenge has no canonical payment requirement."
                    )
                canonical_req = CanonicalPaymentRequirement(
                    scheme=parsed.scheme,
                    network=_normalize_network(parsed.network),
                    chain_id=int(parsed.network.split(":")[1]) if "eip155:" in parsed.network else 137,
                    asset=parsed.asset,
                    token_address_or_mint=credential_parameters.get("token_address") or "",
                    decimals=6,
                    atomic_amount=str(int(parsed.amount * 1000000)),
                    human_amount_decimal=Decimal(str(parsed.amount)),
                    pay_to=credential_parameters.get("destination") or credential_parameters.get("payTo") or "",
                    source_origin="synthesized_in_process_payment"
                )

            private_atomic_amount = getattr(parsed, "_atomic_amount", None)
            atomic_amount_str = private_atomic_amount or canonical_req.atomic_amount
            if parsed.scheme == "exact":
                if not private_atomic_amount:
                    raise PaymentExecutionError(
                        "Fail-Closed: Exact challenge has no canonical atomic amount."
                    )
                if private_atomic_amount != canonical_req.atomic_amount:
                    raise PaymentExecutionError(
                        "Fail-Closed: Canonical atomic amount mismatch."
                    )
                if not raw_accepted:
                    raise PaymentExecutionError(
                        "Fail-Closed: Exact challenge cannot be safely canonicalized without accepts."
                    )
                self._validate_exact_canonical_alignment(parsed, canonical_req, raw_accepted)
            if not atomic_amount_str or atomic_amount_str == "0" or not re.match(r"^[1-9][0-9]*$", atomic_amount_str):
                raise PaymentExecutionError("Fail-Closed: Missing, zero, or invalid format atomic amount.")

            if not canonical_req.pay_to:
                raise PaymentExecutionError("Fail-Closed: Treasury address (payTo) is missing.")

            raw_asset = canonical_req.token_address_or_mint

            if not is_svm_exact:
                if not self.evm_signer:
                    raise PaymentExecutionError(f"Fail-Closed: {parsed.scheme} 決済には evm_signer が必要です。")

                if parsed.scheme == "exact" and canonical_req.chain_id is None:
                    raise PaymentExecutionError("Fail-Closed: Exact EVM challenge has no trusted chain id.")
                chain_id_to_use = (
                    canonical_req.chain_id if parsed.scheme == "exact"
                    else canonical_req.chain_id or 137
                )

                if parsed.scheme == "exact":
                    evm_address_error = None
                    trusted_metadata = None
                    try:
                        validate_evm_address(canonical_req.pay_to, "canonical payTo")
                        validate_evm_address(raw_asset, "canonical token contract")
                        validate_evm_address(self.evm_signer.address, "configured signer address")
                        trusted_metadata = get_trusted_eip3009_metadata(
                            canonical_req.chain_id, raw_asset, canonical_req.asset
                        )
                        if int(canonical_req.decimals) != trusted_metadata.decimals:
                            raise ValueError(
                                "Canonical token decimals do not match trusted metadata."
                            )
                    except Exception as caught_error:
                        evm_address_error = sanitize_error_msg(str(caught_error))
                    if evm_address_error is not None:
                        raise PaymentExecutionError(
                            f"Fail-Closed: Invalid canonical EVM address. {evm_address_error}"
                        ) from None

                    atomic_generator = getattr(
                        self.evm_signer, "generate_eip3009_payload_atomic", None
                    )
                    legacy_generator = getattr(
                        self.evm_signer, "generate_eip3009_payload", None
                    )
                    if not callable(atomic_generator) and not callable(legacy_generator):
                        raise PaymentExecutionError(
                            "Fail-Closed: EVM signer has no supported EIP-3009 capability."
                        )

                    if callable(atomic_generator):
                        if canonical_v1 is None:
                            raise PaymentExecutionError(
                                "Fail-Closed: EVM exact signer has no canonical v1 binding."
                            )
                        expected_nonce = derive_eip3009_requirement_nonce(
                            canonical_v1["requirement_hash"],
                            canonical_v1["idempotency_key"],
                        )
                        signing_now = int(self._clock())
                        # Recheck the approved snapshot immediately before the
                        # signer callback; a prior parser/policy check is not a
                        # sufficient signature-time guarantee.
                        if approved_exact_snapshot is not None:
                            self._assert_approved_exact_signer_snapshot_unchanged(
                                parsed,
                                target_url=url,
                                method=method.upper(),
                                expected_snapshot_json=approved_exact_snapshot_json,
                                expected_canonical_snapshot_json=(
                                    approved_canonical_snapshot_json
                                ),
                            )
                        eip3009_payload = atomic_generator(
                            asset=canonical_req.asset,
                            atomic_amount_str=atomic_amount_str,
                            treasury_address=canonical_req.pay_to,
                            chain_id=chain_id_to_use,
                            token_address=raw_asset,
                            valid_before=int(canonical_v1["expires_at"]),
                            requirement_hash=canonical_v1["requirement_hash"],
                            idempotency_key=canonical_v1["idempotency_key"],
                            now=signing_now,
                        )
                    else:
                        raise PaymentExecutionError(
                            "Fail-Closed: Legacy EVM signer cannot bind the canonical "
                            "expiry and requirement hash."
                        )

                    if approved_exact_snapshot is not None:
                        self._assert_approved_exact_signer_snapshot_unchanged(
                            parsed,
                            target_url=url,
                            method=method.upper(),
                            expected_snapshot_json=approved_exact_snapshot_json,
                            expected_canonical_snapshot_json=(
                                approved_canonical_snapshot_json
                            ),
                        )

                    eip3009_validation_error = None
                    try:
                        validate_eip3009_payload(
                            eip3009_payload,
                            expected_signer=self.evm_signer.address,
                            chain_id=canonical_req.chain_id,
                            token_address=canonical_req.token_address_or_mint,
                            asset=canonical_req.asset,
                            atomic_amount=atomic_amount_str,
                            pay_to=canonical_req.pay_to,
                            now=signing_now,
                            max_valid_before=int(canonical_v1["expires_at"]),
                            expected_nonce=expected_nonce,
                        )
                    except Exception as caught_error:
                        eip3009_validation_error = sanitize_error_msg(str(caught_error))
                    if eip3009_validation_error is not None:
                        raise PaymentExecutionError(
                            f"Fail-Closed: Invalid EIP-3009 signer output. {eip3009_validation_error}"
                        ) from None

                    proof_ref = sha256_prefixed(
                        canonical_json(eip3009_payload)
                    )

                elif parsed.scheme == SchemeType.lnc_evm_transfer.value:
                    attempt_tracker.mark_irreversible()
                    proof_ref = self.evm_signer.execute_lnc_evm_transfer_settlement(
                        canonical_req.asset, float(canonical_req.human_amount_decimal), canonical_req.pay_to, chain_id_to_use,
                        raw_asset, self.evm_rpc_url
                    )

                elif parsed.scheme == SchemeType.lnc_evm_relay.value:
                    attempt_tracker.mark_irreversible()
                    proof_ref = self.evm_signer.execute_lnc_evm_relay_settlement(
                        canonical_req.asset, float(canonical_req.human_amount_decimal), parsed.parameters.get("relayer_endpoint"),
                        canonical_req.pay_to, chain_id_to_use, raw_asset
                    )

                elif parsed.scheme == SchemeType.x402.value:
                    from .crypto.evm import sign_standard_x402_evm
                    proof_ref = sign_standard_x402_evm(self.private_key, parsed)

                if parsed.scheme == "exact":
                    if not raw_accepted:
                        raw_accepted = {
                            "scheme": "exact", "network": canonical_req.network, "asset": raw_asset,
                            "amount": atomic_amount_str, "payTo": canonical_req.pay_to, "maxTimeoutSeconds": 3600,
                            "extra": {"name": "USD Coin", "version": "2"}
                        }

                    raw_resource = dict(
                        credential_parameters.get("_raw_resource") or {}
                    )
                    raw_resource["url"] = canonical_v1["resource_url"]
                    raw_resource.setdefault("description", "Agent Payment")
                    raw_resource.setdefault("mimeType", "application/json")

                    cdp_v2_payload = {
                        "x402Version": 2,
                        "accepted": raw_accepted,
                        "payload": eip3009_payload,
                        "resource": raw_resource
                    }

                    cdp_v2_payload["extensions"] = _bound_x402_extensions(
                        credential_parameters.get("_raw_extensions"),
                        canonical_v1,
                    )

                    encoded_payload = _b64url_encode(cdp_v2_payload)
                    headers["PAYMENT-SIGNATURE"] = encoded_payload
                    headers["Authorization"] = f"x402 {encoded_payload}"
                    headers["X-PAYMENT"] = encoded_payload

                elif parsed.scheme == SchemeType.x402.value:
                    payment_payload = {"proof": proof_ref, "challenge": parsed.parameters.get("challenge", "")}
                    headers["PAYMENT-SIGNATURE"] = _b64url_encode(payment_payload)
                    headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

                else:
                    payload["paymentAuth"] = {
                        "scheme": parsed.scheme, "proof": proof_ref,
                        "chainId": str(chain_id_to_use), "standard_x402": False
                    }
                    headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        elif parsed.scheme == SchemeType.lnc_solana_transfer.value:
            if not self.solana_signer:
                raise PaymentExecutionError("Fail-Closed: solana_signer が必要です。")
            dest = parsed.parameters.get("payTo") or parsed.parameters.get("destination")
            attempt_tracker.mark_irreversible()
            proof_ref = self.solana_signer.execute_lnc_solana_transfer_settlement(
                parsed.asset, parsed.amount, dest, parsed.parameters.get("reference")
            )
            agent_id = getattr(self, "agent_id", "Anonymous")
            payload["paymentAuth"] = {"scheme": parsed.scheme, "proof": proof_ref, "agentId": agent_id}
            headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        elif parsed.scheme in [SchemeType.l402.value, SchemeType.mpp.value, "Payment"]:
            self._validate_lightning_challenge_preflight(parsed)

            if parsed.scheme == "L402":
                is_get = method.upper() == "GET"
                is_empty_payload = not bool(payload)

                use_delegate = (
                    self.prefer_lightninglabs_l402 and
                    _netloc_is_allowlisted(url, self.l402_delegate_allowed_hosts) and
                    is_get and
                    is_empty_payload
                )

                if use_delegate and self.l402_executor:
                    attempt_tracker.mark_irreversible()
                    l402_report = self.l402_executor.execute_l402(url, method, parsed, headers, payload)
                else:
                    from .adapters.l402_delegate import NativeL402Executor
                    if not self.ln_adapter:
                        raise PaymentExecutionError(f"Fail-Closed: L402決済には ln_adapter が必要です。")
                    native_exec = NativeL402Executor(self.ln_adapter)
                    attempt_tracker.mark_irreversible()
                    l402_report = native_exec.execute_l402(url, method, parsed, headers, payload)

                headers["Authorization"] = l402_report.authorization_value
                authorization = getattr(l402_report, "authorization_value", "")
                if canonical_v1 is not None:
                    expected_prefix = f"L402 {parsed.parameters.get('macaroon')}:"
                    if not isinstance(authorization, str) or not authorization.startswith(expected_prefix):
                        raise PaymentExecutionError(
                            "Fail-Closed: L402 executor returned an unbound credential."
                        )
                    credential_preimage = authorization[len(expected_prefix):]
                    if re.fullmatch(r"[a-fA-F0-9]{64}", credential_preimage) is None:
                        raise PaymentExecutionError(
                            "Fail-Closed: L402 executor returned an invalid preimage."
                        )
                    actual_payment_id = hashlib.sha256(
                        bytes.fromhex(credential_preimage)
                    ).hexdigest()
                    if actual_payment_id != canonical_v1["payment_id"]:
                        raise PaymentExecutionError(
                            "Fail-Closed: L402 executor preimage does not match payment identifier."
                        )
                    proof_ref = f"sha256:{actual_payment_id}"
                else:
                    proof_ref = getattr(l402_report, "preimage", None) or ""
                headers["Authorization"] = authorization
                network_name = "Lightning"

            else:
                if not self.ln_adapter:
                    raise PaymentExecutionError(f"Fail-Closed: {parsed.scheme} 決済には ln_adapter が必要です。")
                invoice = parsed.parameters.get("invoice")
                if not invoice:
                    raise InvoiceParseError("Fail-Closed: Challenge にインボイスが含まれていません。")

                attempt_tracker.mark_irreversible()
                proof_ref = self.ln_adapter.pay_invoice(invoice)

                if canonical_v1 is not None:
                    if not isinstance(proof_ref, str) or re.fullmatch(
                        r"[a-fA-F0-9]{64}", proof_ref
                    ) is None:
                        raise PaymentExecutionError(
                            "Fail-Closed: Lightning provider returned an invalid preimage."
                        )
                    actual_payment_id = hashlib.sha256(
                        bytes.fromhex(proof_ref)
                    ).hexdigest()
                    if actual_payment_id != canonical_v1["payment_id"]:
                        raise PaymentExecutionError(
                            "Fail-Closed: Lightning provider preimage does not match payment identifier."
                        )
                    credential_preimage = proof_ref
                    proof_ref = f"sha256:{actual_payment_id}"
                else:
                    credential_preimage = proof_ref

                charge_id = parsed.parameters.get("charge")
                if charge_id:
                    headers["Authorization"] = f"{parsed.scheme} {charge_id}:{credential_preimage}"
                else:
                    headers["Authorization"] = f"{parsed.scheme} {credential_preimage}"

        return proof_ref, network_name, l402_report

    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        result = self.execute_detailed(method, endpoint_path, payload, headers)
        return result.response

    def _resolve_next_action(self, error_data: dict, headers: dict) -> Tuple[Optional[NextAction], str]:
        if "next_action" in error_data and isinstance(error_data["next_action"], dict):
            try:
                return NextAction(**error_data["next_action"]), "canonical_body"
            except Exception:
                pass

        for alias_key in ["next", "action", "retry_action"]:
            if alias_key in error_data and isinstance(error_data[alias_key], dict):
                raw = error_data[alias_key]
                try:
                    return NextAction(
                        instruction_for_agent=raw.get("instruction_for_agent") or raw.get("instruction") or raw.get("message_for_agent") or "Resolved from alias",
                        method=raw.get("method", "GET"),
                        url=raw.get("url"),
                        suggested_payload=raw.get("suggested_payload") or raw.get("payload") or raw.get("body"),
                        suggested_headers=raw.get("suggested_headers") or raw.get("headers")
                    ), "alias_body"
                except Exception:
                    pass

        location = headers.get("Location") or headers.get("location")
        if location and isinstance(location, str):
            return NextAction(instruction_for_agent="Follow Location header", method="GET", url=location), "location_header"

        link_header = headers.get("Link") or headers.get("link")
        if link_header and isinstance(link_header, str):
            match = re.search(r'<([^>]+)>;\s*rel="?(next|payment)"?', link_header)
            if match:
                return NextAction(instruction_for_agent=f"Follow Link rel={match.group(2)}", method="GET", url=match.group(1)), "link_header"

        return None, "none"

    def _resolve_url(self, endpoint_path: str) -> str:
        if endpoint_path.startswith("http://") or endpoint_path.startswith("https://"):
            return endpoint_path

        base = getattr(self, "base_url", "") or "https://kari.mayim-mayim.com"
        return f"{base.rstrip('/')}/{endpoint_path.lstrip('/')}"

    def _resolve_navigation(
        self, current_url: str, next_url: str, headers: dict, method: str,
        is_redirect: bool, allowed_hosts: list,
        context: Optional[ExecutionContext] = None,
        fingerprint: Optional[str] = None,
    ) -> Tuple[str, dict, bool]:
        raw_absolute_next = urljoin(current_url, next_url)
        validated_target = validate_redirect_target(
            raw_absolute_next, resolver=self._navigation_resolver
        )
        absolute_next = validated_target.url
        old_target = canonicalize_http_target(current_url)
        old_o = urlparse(old_target.url)
        new_o = urlparse(absolute_next)

        if old_o.scheme.lower() == 'https' and new_o.scheme.lower() == 'http':
            raise NavigationGuardrailError("HTTPS to HTTP downgrade denied.")

        def _get_port(p): return p.port or (443 if p.scheme.lower() == 'https' else 80)

        old_hostname = (old_o.hostname or "").lower()
        new_hostname = (new_o.hostname or "").lower()
        is_cross_origin = (
            old_o.scheme.lower() != new_o.scheme.lower() or
            old_hostname != new_hostname or
            _get_port(old_o) != _get_port(new_o)
        )

        is_different_path = old_o.path != new_o.path or old_o.query != new_o.query

        safe_headers = dict(headers)
        if is_cross_origin or is_different_path:
            allowed = {_normalize_policy_netloc(h) for h in allowed_hosts}
            destination_authority = _strict_netloc_from_url(absolute_next)
            if is_cross_origin and destination_authority not in allowed and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Cross-origin redirect to {absolute_next} denied.")

            safe_headers = _strip_sensitive_headers(safe_headers)
            if is_cross_origin:
                safe_headers = {
                    k: v for k, v in safe_headers.items()
                    if _normalize_secret_name(k) not in {"host", "content-length"}
                }

        if is_redirect and method.upper() not in ("GET", "HEAD"):
            raise NavigationGuardrailError("[Guardrail] Unsafe method conversion on redirect denied.")

        # Hints and allow_unsafe_navigate can govern navigation consent, but can
        # never widen the client's local blocked/allowed host policy.
        self._check_local_policy(absolute_next)
        if context is not None and fingerprint is not None:
            self._claim_navigation_target(context, fingerprint, absolute_next)
            with context._payment_state_lock:
                # Query materialization happens after navigation extraction for
                # GET requests.  Pin the canonical origin, not the pre-query
                # URL, so adding approved query parameters cannot trigger a
                # second hostname lookup at transport time.
                pin_origin = canonicalize_http_target(absolute_next).origin
                context._navigation_pins[pin_origin] = validated_target.addresses
        return absolute_next, safe_headers, is_cross_origin

    def _pinned_transport_request(
        self,
        context: ExecutionContext,
        url: str,
        headers: Mapping[str, Any],
    ) -> Tuple[str, Dict[str, Any], Optional[str]]:
        """Return an IP-pinned URL, original Host header, and TLS SNI name.

        Only validated navigation targets have a pin.  Initial user-selected
        destinations retain the ordinary transport behavior; redirects and
        HATEOAS destinations never perform a second DNS lookup at connect time.
        """
        canonical = canonicalize_http_target(url)
        self._init_context_state(context)
        with context._payment_state_lock:
            addresses = tuple(
                context._navigation_pins.get(canonical.origin, ())
            )
        if not addresses:
            return url, dict(headers), None

        address = addresses[0]
        display_address = f"[{address}]" if ":" in address else address
        default_port = 443 if canonical.scheme == "https" else 80
        authority = (
            display_address
            if canonical.port == default_port
            else f"{display_address}:{canonical.port}"
        )
        parsed = urlsplit(canonical.url)
        pinned_url = urlunsplit(
            (canonical.scheme, authority, parsed.path, parsed.query, "")
        )

        safe_headers = {
            key: value for key, value in dict(headers).items()
            if not (isinstance(key, str) and key.casefold() == "host")
        }
        safe_headers["Host"] = canonical.origin.split("://", 1)[1]
        # A connection authenticated for one original hostname must not be
        # pooled under the shared IP URL and reused for a different hostname.
        safe_headers["Connection"] = "close"
        return pinned_url, safe_headers, canonical.host

    def _request_sync(
        self,
        method: str,
        url: str,
        req_kwargs: Dict[str, Any],
        context: ExecutionContext,
    ):
        transport_url, transport_headers, server_hostname = self._pinned_transport_request(
            context, url, req_kwargs.get("headers", {})
        )
        wire_kwargs = dict(req_kwargs)
        wire_kwargs["headers"] = transport_headers
        if server_hostname is None or requests.request is not _ORIGINAL_REQUESTS_REQUEST:
            return requests.request(method, transport_url, **wire_kwargs)

        # Bypass environment proxies for a pinned destination; otherwise the
        # proxy could perform its own untrusted DNS resolution.  For HTTPS the
        # adapter verifies the certificate and SNI against the original host.
        session = requests.Session()
        session.trust_env = False
        if transport_url.startswith("https://"):
            session.mount("https://", _PinnedHTTPSAdapter(server_hostname))
        try:
            return session.request(method, transport_url, **wire_kwargs)
        finally:
            session.close()

    async def _request_async(
        self,
        method: str,
        url: str,
        req_kwargs: Dict[str, Any],
        context: ExecutionContext,
    ):
        transport_url, transport_headers, server_hostname = self._pinned_transport_request(
            context, url, req_kwargs.get("headers", {})
        )
        wire_kwargs = dict(req_kwargs)
        wire_kwargs["headers"] = transport_headers
        if server_hostname is not None:
            wire_kwargs["extensions"] = {"sni_hostname": server_hostname}
        return await self._async_client.request(method, transport_url, **wire_kwargs)

    def _prepare_hateoas_navigation(
        self, current_url: str, next_url: str, next_method: str,
        original_headers: dict, suggested_headers: Optional[dict],
        original_payload: dict, suggested_payload: Optional[dict],
        allowed_hosts: list,
        context: Optional[ExecutionContext] = None,
        fingerprint: Optional[str] = None,
    ) -> Tuple[str, dict, dict, bool]:
        """Apply one navigation sanitizer shared by sync and async callers."""
        safe_headers = _strip_sensitive_headers(original_headers)
        safe_headers.update(_strip_sensitive_headers(suggested_headers))
        safe_headers = {
            key: value for key, value in safe_headers.items()
            if _normalize_secret_name(key) not in {"host", "content-length"}
        }
        absolute_next, safe_headers, is_cross_origin = self._resolve_navigation(
            current_url, next_url, safe_headers, next_method, False, allowed_hosts,
            context=context, fingerprint=fingerprint,
        )

        safe_suggested_payload = _strip_payload_secrets(suggested_payload or {})
        if not isinstance(safe_suggested_payload, dict):
            raise NavigationGuardrailError("Fail-Closed: HATEOAS payload must be an object.")
        if is_cross_origin:
            safe_payload = safe_suggested_payload
        else:
            safe_payload = _strip_payload_secrets(original_payload or {})
            if not isinstance(safe_payload, dict):
                raise NavigationGuardrailError("Fail-Closed: HATEOAS payload must be an object.")
            safe_payload.update(safe_suggested_payload)
        return absolute_next, safe_headers, safe_payload, is_cross_origin

    def execute_detailed(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None,
        _current_hop: int = 0, _payment_retry_count: int = 0,
        context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None
    ) -> ExecutionResult:
        return self._execute_detailed_internal(
            method, endpoint_path, payload, headers, _current_hop,
            _payment_retry_count, context, outcome_matcher, _current_receipt,
        )

    def _execute_detailed_internal(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None,
        headers: Optional[dict] = None, _current_hop: int = 0,
        _payment_retry_count: int = 0, context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None,
        _fingerprint: Optional[str] = None
    ) -> ExecutionResult:

        url = self._resolve_url(endpoint_path)
        self._check_local_policy(url)
        payload = payload or {}
        method_upper = method.upper()

        context = context or ExecutionContext()
        self._restore_session_spend_from_evidence(context)

        headers = dict(headers or {})

        idemp_present, supplied_idemp_key = self._extract_idempotency_key(headers)
        headers = {k: v for k, v in headers.items() if k.lower() != "idempotency-key"}

        logical_idemp_key, idemp_key = self._logical_and_wire_idempotency_key(
            context,
            url,
            supplied_idemp_key,
            initialize=_fingerprint is None and idemp_present,
        )

        initial_wire_url = self._final_wire_url(method_upper, url, payload)
        fingerprint = _fingerprint or self._compute_fingerprint(
            method_upper,
            initial_wire_url,
            {} if method_upper == "GET" else payload,
            logical_idemp_key,
        )
        self._initialize_navigation_state(context, fingerprint, initial_wire_url)

        if not any(k.lower() == "user-agent" for k in headers.keys()):
            headers["User-Agent"] = CUSTOM_USER_AGENT

        res = None

        if self.max_hops == 0 and _current_hop > 0:
            raise PaymentExecutionError("API Error 302: Redirects disabled by max_hops=0")

        while True:
            if idemp_key:
                headers["Idempotency-Key"] = idemp_key
            else:
                headers = {
                    key: value for key, value in headers.items()
                    if key.lower() != "idempotency-key"
                }
            wire_url = self._final_wire_url(method_upper, url, payload)
            req_kwargs = {
                "json": None if method_upper == "GET" else payload,
                # GET parameters are already part of wire_url so the approved
                # URL and transport URL cannot diverge or be appended twice.
                "params": None,
                "headers": headers,
                "allow_redirects": False
            }

            request_error_type = None
            try:
                res = self._request_sync(method_upper, wire_url, req_kwargs, context)
            except requests.RequestException as caught_error:
                request_error_type = caught_error.__class__
            if request_error_type is not None:
                if _current_receipt is not None:
                    raise PaymentExecutionError(
                        "Ambiguous payment error: paid retry transport failed."
                    ) from None
                raise _new_sanitized_exception(
                    request_error_type,
                    "Network request failed before payment processing.",
                ) from None

            if res.status_code in (301, 302, 303, 307, 308):
                if (
                    _current_receipt is not None
                    and _current_receipt.scheme == "exact"
                    and not _current_receipt.payment_performed
                ):
                    raise PaymentExecutionError(
                        "Ambiguous payment error: exact credential retry redirected."
                    )
                if self.max_hops == 0:
                    raise PaymentExecutionError(f"API Error {res.status_code}: Redirects disabled by max_hops=0")
                location = res.headers.get("Location") or res.headers.get("location")
                if not location:
                    break

                url, headers, is_cross_origin = self._resolve_navigation(
                    wire_url, location, headers, method_upper, True,
                    context.hints.get("allowed_hosts", []),
                    context=context, fingerprint=fingerprint,
                )
                payload = {} if is_cross_origin else _strip_payload_secrets(payload)
                _, idemp_key = self._logical_and_wire_idempotency_key(
                    context, url
                )
                continue

            if 200 <= res.status_code < 300:
                try:
                    raw_json = res.json() if res.content else {"status": "success"}
                    resp_data = raw_json if isinstance(raw_json, dict) else {"status": "success", "data": raw_json}
                except Exception:
                    resp_data = {"status": "success", "message": "unparseable"}

                result = ExecutionResult(
                    response=resp_data,
                    final_url=wire_url,
                    retry_count=_payment_retry_count,
                    response_headers=_strip_sensitive_headers(res.headers)
                )

                self._apply_server_receipt_state(
                    _current_receipt, res.headers, res.status_code
                )

                if outcome_matcher:
                    context.hints["target_url"] = wire_url
                    context.hints["http_method"] = method

                    sig = inspect.signature(outcome_matcher)
                    if len(sig.parameters) == 3:
                        result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                    else:
                        result.outcome = outcome_matcher(resp_data, context)

                sponsored_ev = None
                sandbox_ev = None
                if resp_data.get("access_path") == "sponsored_grant":
                    grant_diag = getattr(self, "_last_grant_diagnostics", None)
                    grant_token = getattr(self, "grant_token", None)
                    sponsored_ev = build_sponsored_access_evidence(grant_diagnostics=grant_diag, response_body=resp_data, grant_token=grant_token)
                    self._last_sponsored_access_evidence = sponsored_ev

                if resp_data.get("evidence_ref") or resp_data.get("meta", {}).get("kind") == "sandbox_result":
                    sandbox_ev = build_sandbox_evidence_from_response(resp_data)
                    if sandbox_ev:
                        self._last_sandbox_evidence = sandbox_ev

                if getattr(self, "evidence_repo", None):
                    if _payment_retry_count == 0 and _current_hop == 0 and (sponsored_ev or sandbox_ev):
                        record = PaymentEvidenceRecord(
                            session_id=context.session_id, correlation_id=context.correlation_id,
                            target_url=wire_url, method=method, outcome=result.outcome,
                            sponsored_access=sponsored_ev, sandbox=sandbox_ev
                        )
                        self._export_evidence_best_effort(record, context)

                return result

            if res.status_code == 402:
                self._assert_payment_state_allows_402(context, fingerprint)
                if _payment_retry_count >= self.max_payment_retries:
                    self._update_payment_state(context, fingerprint, "ambiguous")
                    raise PaymentExecutionError("Ambiguous payment error: Max 402 retries exceeded.")

                try:
                    parsed = self._parse_challenge(
                        res,
                        expected_asset=payload.get("asset", "SATS"),
                        expected_chain_id=str(payload.get("chainId")) if payload.get("chainId") else None,
                        request_url=wire_url,
                        method=method_upper,
                        idempotency_key=idemp_key,
                    )
                except Exception:
                    self._update_payment_state(
                        context, fingerprint, "validation_failed"
                    )
                    raise
                self._last_parsed_challenge = parsed

                if self.evidence_repo:
                    past_records = self._import_evidence_best_effort(wire_url, context)
                    if past_records:
                        context.past_evidence = past_records

                evidence = TrustEvidence(url=wire_url, challenge=parsed, host_metadata={}, agent_hints=context.hints)

                decision = None
                for evaluator in self.trust_evaluators:
                    sig = inspect.signature(evaluator)
                    if len(sig.parameters) == 2:
                        decision = evaluator(evidence, context)
                    else:
                        decision = evaluator(wire_url, parsed, context)
                    if not decision.is_trusted:
                        if getattr(self, "evidence_repo", None):
                            record = PaymentEvidenceRecord(
                                session_id=context.session_id, correlation_id=context.correlation_id,
                                target_url=wire_url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                                trust_decision=decision, error_message=f"CounterpartyTrustError: {decision.reason}",
                            )
                            self._export_evidence_best_effort(record, context)
                        raise CounterpartyTrustError(
                            "Trust Evaluation Blocked Payment: "
                            + redact_urls_in_text(
                                sanitize_error_msg(decision.reason)
                            )
                        )

                self._check_and_set_payment_state(context, fingerprint)

                payment_completed = False
                payment_performed = False
                delta_usd = None
                receipt = None
                attempt_tracker = _PaymentAttemptTracker()
                deferred_error_type = None
                deferred_error_message = None
                deferred_error_record = None
                approval_completed = False
                approved_receipt_snapshot = None
                credential_generated = False
                credential_only = False
                credential_reused = False
                session_budget_reserved = False

                try:
                    self._approve_payment_requirement(
                        parsed,
                        target_url=wire_url,
                        method=method_upper,
                        context=context,
                        fingerprint=fingerprint,
                    )
                    approval_completed = True
                    approved_receipt_snapshot = (
                        self._capture_approved_receipt_snapshot(parsed)
                    )
                    self._preflight_approved_payment_before_session_budget(
                        parsed,
                        approved_receipt_snapshot,
                        target_url=wire_url,
                        method=method_upper,
                    )
                    self._reserve_session_budget(
                        context,
                        fingerprint,
                        approved_receipt_snapshot["usd_value"],
                    )
                    session_budget_reserved = True
                    proof_ref, network_name, l402_report = self._process_payment(
                        parsed, headers, payload, method=method, url=wire_url,
                        _attempt_tracker=attempt_tracker,
                    )
                    self._assert_approved_receipt_snapshot_unchanged(
                        parsed,
                        approved_receipt_snapshot,
                        target_url=wire_url,
                        method=method_upper,
                    )

                    credential_generated = True
                    canonical_requirement = json.loads(
                        approved_receipt_snapshot["canonical_snapshot_json"]
                    )
                    credential_only = (
                        parsed.scheme == "exact"
                        and canonical_requirement["rail"] == "x402"
                    )

                    payment_performed = not (
                        l402_report and not getattr(l402_report, "payment_performed", True)
                    )
                    if credential_only:
                        # A signed authorization is a credential, not proof of
                        # settlement.  Keep its reservation pending until the
                        # paid request produces a response.
                        payment_performed = False
                    elif not payment_performed:
                        credential_reused = True
                        self._release_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "credential_reused")
                    else:
                        self._confirm_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "completed")
                        context._payment_executed = True

                    payment_completed = payment_performed and not credential_only
                    delta_usd = (
                        float(Decimal(approved_receipt_snapshot["usd_value"]))
                        if payment_performed
                        else 0.0
                    )

                    receipt = self._new_settlement_receipt(
                        parsed,
                        network_name,
                        proof_ref,
                        l402_report,
                        wire_url,
                        fingerprint,
                        approved_snapshot=approved_receipt_snapshot,
                        payment_performed=payment_performed,
                    )
                    self.last_receipt = receipt

                    if credential_only:
                        # From this point the credential-bearing request may
                        # reach the provider even if its response is lost.
                        attempt_tracker.mark_irreversible()

                    next_result = self._execute_detailed_internal(
                        method, url, payload, headers, _current_hop, _payment_retry_count + 1,
                        context=context, outcome_matcher=outcome_matcher, _current_receipt=receipt, _fingerprint=fingerprint
                    )

                    if credential_only:
                        self._confirm_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "completed")
                        context._payment_executed = True
                        payment_performed = True
                        payment_completed = True
                        delta_usd = float(
                            Decimal(approved_receipt_snapshot["usd_value"])
                        )
                        receipt.payment_performed = True

                    next_result.settlement_receipt = receipt
                    next_result.used_scheme = receipt.scheme
                    next_result.used_asset = receipt.asset
                    next_result.verification_status = receipt.verification_status

                    if self.evidence_repo:
                        record = PaymentEvidenceRecord(
                            session_id=context.session_id, correlation_id=context.correlation_id,
                            target_url=wire_url, method=method, scheme=receipt.scheme,
                            asset=receipt.asset, amount=receipt.settled_amount,
                            trust_decision=decision, receipt_summary={"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status},
                            outcome=next_result.outcome, session_spend_delta_usd=delta_usd,
                            session_budget_event="confirmed",
                            session_budget_operation_id=fingerprint,
                            session_budget_amount_usd=delta_usd,
                            delegate_source=getattr(l402_report, "delegate_source", "native") if l402_report else "native",
                            payment_hash=getattr(l402_report, "payment_hash", None) if l402_report else None,
                            fee_sats=getattr(l402_report, "fee_sats", None) if l402_report else None,
                            cached_token_used=getattr(l402_report, "cached_token_used", False) if l402_report else False,
                            payment_performed=getattr(l402_report, "payment_performed", True) if l402_report else True,
                            sponsored_access=getattr(self, "_last_sponsored_access_evidence", None),
                            sandbox=getattr(self, "_last_sandbox_evidence", None)
                        )
                        self._export_evidence_best_effort(record, context)

                    return next_result

                except Exception as caught_error:
                    error_type = caught_error.__class__
                    irreversible_or_paid = (
                        (
                            attempt_tracker.irreversible_attempt_started
                            and not credential_reused
                        )
                        or payment_completed
                    )

                    reserve_delta = 0.0
                    if credential_reused:
                        self._release_session_budget(context, fingerprint)
                        self._update_payment_state(
                            context, fingerprint, "credential_reused"
                        )
                    elif (
                        credential_only
                        and credential_generated
                        and attempt_tracker.irreversible_attempt_started
                        and not payment_completed
                    ):
                        reserve_delta = float(
                            self._mark_session_budget_unknown(
                                context, fingerprint
                            )
                        )
                        self._update_payment_state(
                            context, fingerprint, "settlement_unknown"
                        )
                    elif payment_completed:
                        self._mark_known_settled_ambiguity(context, fingerprint)
                    elif attempt_tracker.irreversible_attempt_started:
                        reserve_delta = self._reserve_ambiguous_spend(
                            context,
                            fingerprint,
                            parsed,
                            approved_usd_value=(
                                approved_receipt_snapshot["usd_value"]
                                if approved_receipt_snapshot is not None
                                else None
                            ),
                        )
                        self._update_payment_state(context, fingerprint, "ambiguous")
                    elif session_budget_reserved:
                        self._release_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "validation_failed")
                    else:
                        self._update_payment_state(
                            context, fingerprint, "validation_failed"
                        )

                    if credential_reused:
                        final_err = "credential_delivery_failed"
                        deferred_error_type = PaymentExecutionError
                        deferred_error_message = final_err
                    elif irreversible_or_paid:
                        final_err = (
                            "settlement_unknown"
                            if credential_only and not payment_completed
                            else "ambiguous_payment_result"
                        )
                        deferred_error_type = PaymentExecutionError
                        deferred_error_message = f"Ambiguous payment error: {final_err}"
                    else:
                        final_err = "payment_validation_failed_before_irreversible_processing"
                        deferred_error_type = error_type
                        if isinstance(caught_error, PaymentExecutionError):
                            deferred_error_message = sanitize_error_msg(
                                str(caught_error)
                            )
                        else:
                            deferred_error_message = final_err

                    if self.evidence_repo:
                        evidence_projection = approved_receipt_snapshot or {
                            "scheme": parsed.scheme,
                            "asset": parsed.asset,
                            "amount": parsed.amount,
                        }
                        record_kwargs = {
                            "session_id": context.session_id, "correlation_id": context.correlation_id,
                            "target_url": wire_url, "method": method,
                            "scheme": evidence_projection["scheme"],
                            "asset": evidence_projection["asset"],
                            "amount": evidence_projection["amount"],
                            "trust_decision": decision, "error_message": final_err,
                            "sponsored_access": getattr(self, "_last_sponsored_access_evidence", None),
                            "sandbox": getattr(self, "_last_sandbox_evidence", None)
                        }
                        if (
                            not attempt_tracker.irreversible_attempt_started
                            and not payment_completed
                        ):
                            record_kwargs["payment_performed"] = False
                            record_kwargs["session_spend_delta_usd"] = 0.0
                        if credential_only and not payment_completed:
                            record_kwargs["payment_performed"] = False
                        if payment_completed:
                            record_kwargs["session_spend_delta_usd"] = delta_usd
                            record_kwargs["session_budget_event"] = "confirmed"
                            record_kwargs["session_budget_operation_id"] = fingerprint
                            record_kwargs["session_budget_amount_usd"] = delta_usd
                        elif reserve_delta > 0:
                            # Unknown settlement remains a reservation.  It is
                            # deliberately excluded from the confirmed-spend
                            # compatibility projection.
                            record_kwargs["payment_performed"] = False
                            record_kwargs["session_spend_delta_usd"] = 0.0
                            record_kwargs["session_budget_event"] = "reserved"
                            record_kwargs["session_budget_operation_id"] = fingerprint
                            record_kwargs["session_budget_amount_usd"] = reserve_delta
                            if receipt is not None:
                                record_kwargs["receipt_summary"] = {
                                    "receipt_id": receipt.receipt_id,
                                    "verification_status": receipt.verification_status,
                                }
                        if payment_completed and receipt is not None:
                            record_kwargs["receipt_summary"] = {"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status}

                        deferred_error_record = PaymentEvidenceRecord(**record_kwargs)

                if deferred_error_record is not None:
                    self._export_evidence_best_effort(deferred_error_record, context)
                if deferred_error_type is not None:
                    raise _new_sanitized_exception(
                        deferred_error_type, deferred_error_message
                    ) from None

            break

        if (
            _current_receipt is not None
            and _current_receipt.scheme == "exact"
            and not _current_receipt.payment_performed
        ):
            raise PaymentExecutionError(
                "Ambiguous payment error: exact credential retry did not "
                "receive a direct success response."
            )

        try:
            error_data = res.json()
        except Exception:
            error_data = {}

        next_action, source = self._resolve_next_action(error_data, res.headers)

        if self.auto_navigate and next_action:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()

            is_unsafe = next_method not in ["GET", "HEAD"]

            if is_unsafe and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")

            if next_url and next_method != "NONE":
                next_url, merged_headers, merged_payload, is_cross_origin = self._prepare_hateoas_navigation(
                    url, next_url, next_method, headers, next_action.suggested_headers,
                    payload, next_action.suggested_payload,
                    context.hints.get("allowed_hosts", []),
                    context=context, fingerprint=fingerprint,
                )
                _, next_wire_key = self._logical_and_wire_idempotency_key(
                    context, next_url
                )
                merged_headers["Idempotency-Key"] = next_wire_key

                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                next_result = self._execute_detailed_internal(
                    next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count,
                    context=context, outcome_matcher=outcome_matcher, _current_receipt=_current_receipt,
                    _fingerprint=fingerprint
                )

                if self.evidence_repo:
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, navigation_source=source, outcome=next_result.outcome,
                        sponsored_access=getattr(self, "_last_sponsored_access_evidence", None),
                        sandbox=getattr(self, "_last_sandbox_evidence", None)
                    )
                    self._export_evidence_best_effort(record, context)
                return next_result

        error_msg = sanitize_error_msg(error_data.get('message', res.text) if res else "No response")
        status_c = res.status_code if res else 500
        raise PaymentExecutionError(f"API Error {status_c}: {error_msg}")

    async def execute_request_async(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        result = await self.execute_detailed_async(method, endpoint_path, payload, headers)
        return result.response

    async def execute_detailed_async(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None,
        _current_hop: int = 0, _payment_retry_count: int = 0,
        context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None
    ) -> ExecutionResult:
        return await self._execute_detailed_async_internal(
            method, endpoint_path, payload, headers, _current_hop,
            _payment_retry_count, context, outcome_matcher, _current_receipt,
        )

    async def _execute_detailed_async_internal(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None,
        headers: Optional[dict] = None, _current_hop: int = 0,
        _payment_retry_count: int = 0, context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None,
        _fingerprint: Optional[str] = None
    ) -> ExecutionResult:

        url = self._resolve_url(endpoint_path)
        self._check_local_policy(url)
        payload = payload or {}
        method_upper = method.upper()

        context = context or ExecutionContext()
        await self._restore_session_spend_from_evidence_async(context)

        headers = dict(headers or {})

        idemp_present, supplied_idemp_key = self._extract_idempotency_key(headers)
        headers = {k: v for k, v in headers.items() if k.lower() != "idempotency-key"}

        logical_idemp_key, idemp_key = self._logical_and_wire_idempotency_key(
            context,
            url,
            supplied_idemp_key,
            initialize=_fingerprint is None and idemp_present,
        )

        initial_wire_url = self._final_wire_url(method_upper, url, payload)
        fingerprint = _fingerprint or self._compute_fingerprint(
            method_upper,
            initial_wire_url,
            {} if method_upper == "GET" else payload,
            logical_idemp_key,
        )
        self._initialize_navigation_state(context, fingerprint, initial_wire_url)

        if idemp_key:
            headers["Idempotency-Key"] = idemp_key

        if not any(k.lower() == "user-agent" for k in headers.keys()):
            headers["User-Agent"] = CUSTOM_USER_AGENT

        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                follow_redirects=False, trust_env=False
            )

        res = None

        if self.max_hops == 0 and _current_hop > 0:
             raise PaymentExecutionError("API Error 302: Redirects disabled by max_hops=0")

        while True:
            if idemp_key:
                headers["Idempotency-Key"] = idemp_key
            else:
                headers = {
                    key: value for key, value in headers.items()
                    if key.lower() != "idempotency-key"
                }
            wire_url = self._final_wire_url(method_upper, url, payload)
            req_kwargs = {
                "json": None if method_upper == "GET" else payload,
                "params": None,
                "headers": headers,
                "follow_redirects": False
            }

            request_error_type = None
            try:
                res = await self._request_async(
                    method_upper, wire_url, req_kwargs, context
                )
            except httpx.RequestError as caught_error:
                request_error_type = caught_error.__class__
            if request_error_type is not None:
                if _current_receipt is not None:
                    raise PaymentExecutionError(
                        "Ambiguous payment error: paid retry transport failed."
                    ) from None
                raise _new_sanitized_exception(
                    request_error_type,
                    "Network request failed before payment processing.",
                ) from None

            if res.status_code in (301, 302, 303, 307, 308):
                if (
                    _current_receipt is not None
                    and _current_receipt.scheme == "exact"
                    and not _current_receipt.payment_performed
                ):
                    raise PaymentExecutionError(
                        "Ambiguous payment error: exact credential retry redirected."
                    )
                if self.max_hops == 0:
                    raise PaymentExecutionError(f"API Error {res.status_code}: Redirects disabled by max_hops=0")
                location = res.headers.get("Location") or res.headers.get("location")
                if not location:
                    break

                url, headers, is_cross_origin = self._resolve_navigation(
                    wire_url, location, headers, method_upper, True,
                    context.hints.get("allowed_hosts", []),
                    context=context, fingerprint=fingerprint,
                )
                payload = {} if is_cross_origin else _strip_payload_secrets(payload)
                _, idemp_key = self._logical_and_wire_idempotency_key(
                    context, url
                )
                continue

            if 200 <= res.status_code < 300:
                try:
                    raw_json = res.json() if res.content else {"status": "success"}
                    resp_data = raw_json if isinstance(raw_json, dict) else {"status": "success", "data": raw_json}
                except Exception:
                    resp_data = {"status": "success", "message": "unparseable"}

                result = ExecutionResult(
                    response=resp_data,
                    final_url=wire_url,
                    retry_count=_payment_retry_count,
                    response_headers=_strip_sensitive_headers(res.headers)
                )

                self._apply_server_receipt_state(
                    _current_receipt, res.headers, res.status_code
                )

                if outcome_matcher:
                    context.hints["target_url"] = wire_url
                    context.hints["http_method"] = method

                    loop = asyncio.get_running_loop()
                    sig = inspect.signature(outcome_matcher)
                    if len(sig.parameters) == 3:
                        result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                    else:
                        result.outcome = outcome_matcher(resp_data, context)

                sponsored_ev = None
                sandbox_ev = None

                if resp_data.get("access_path") == "sponsored_grant":
                    grant_diag = getattr(self, "_last_grant_diagnostics", None)
                    grant_token = getattr(self, "grant_token", None)
                    sponsored_ev = build_sponsored_access_evidence(
                        grant_diagnostics=grant_diag,
                        response_body=resp_data,
                        grant_token=grant_token
                    )
                    self._last_sponsored_access_evidence = sponsored_ev

                if resp_data.get("evidence_ref") or resp_data.get("meta", {}).get("kind") == "sandbox_result":
                    sandbox_ev = build_sandbox_evidence_from_response(resp_data)
                    if sandbox_ev:
                        self._last_sandbox_evidence = sandbox_ev

                if getattr(self, "evidence_repo", None):
                    if _payment_retry_count == 0 and _current_hop == 0 and (sponsored_ev or sandbox_ev):
                        record = PaymentEvidenceRecord(
                            session_id=context.session_id, correlation_id=context.correlation_id,
                            target_url=wire_url, method=method,
                            outcome=result.outcome,
                            sponsored_access=sponsored_ev,
                            sandbox=sandbox_ev
                        )
                        await self._export_evidence_best_effort_async(record, context)

                return result

            if res.status_code == 402:
                self._assert_payment_state_allows_402(context, fingerprint)
                if _payment_retry_count >= self.max_payment_retries:
                    self._update_payment_state(context, fingerprint, "ambiguous")
                    raise PaymentExecutionError("Ambiguous payment error: Max 402 retries exceeded")

                try:
                    parsed = self._parse_challenge(
                        res,
                        expected_asset=payload.get("asset", "SATS"),
                        expected_chain_id=str(payload.get("chainId")) if payload.get("chainId") else None,
                        request_url=wire_url,
                        method=method_upper,
                        idempotency_key=idemp_key,
                    )
                except Exception:
                    self._update_payment_state(
                        context, fingerprint, "validation_failed"
                    )
                    raise
                self._last_parsed_challenge = parsed

                if getattr(self, "evidence_repo", None):
                    past_records = await self._import_evidence_best_effort_async(
                        wire_url, context
                    )
                    if past_records:
                        context.past_evidence = past_records

                evidence = TrustEvidence(
                    url=wire_url,
                    challenge=parsed,
                    host_metadata={},
                    agent_hints=context.hints
                )

                decision = None
                for evaluator in self.trust_evaluators:
                    sig = inspect.signature(evaluator)
                    loop = asyncio.get_running_loop()
                    if len(sig.parameters) == 2:
                        decision = await loop.run_in_executor(None, evaluator, evidence, context)
                    else:
                        decision = await loop.run_in_executor(None, evaluator, wire_url, parsed, context)

                    if not decision.is_trusted:
                        if getattr(self, "evidence_repo", None):
                            record = PaymentEvidenceRecord(
                                session_id=context.session_id, correlation_id=context.correlation_id,
                                target_url=wire_url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                                trust_decision=decision, error_message=f"CounterpartyTrustError: {decision.reason}",
                            )
                            await self._export_evidence_best_effort_async(
                                record, context
                            )
                        raise CounterpartyTrustError(
                            "Trust Evaluation Blocked Payment: "
                            + redact_urls_in_text(
                                sanitize_error_msg(decision.reason)
                            )
                        )

                self._check_and_set_payment_state(context, fingerprint)

                payment_completed = False
                payment_performed = False
                delta_usd = None
                receipt = None
                attempt_tracker = _PaymentAttemptTracker()
                deferred_error_type = None
                deferred_error_message = None
                deferred_error_record = None
                approval_completed = False
                approved_receipt_snapshot = None
                credential_generated = False
                credential_only = False
                credential_reused = False
                session_budget_reserved = False

                try:
                    self._approve_payment_requirement(
                        parsed,
                        target_url=wire_url,
                        method=method_upper,
                        context=context,
                        fingerprint=fingerprint,
                    )
                    approval_completed = True
                    approved_receipt_snapshot = (
                        self._capture_approved_receipt_snapshot(parsed)
                    )
                    self._preflight_approved_payment_before_session_budget(
                        parsed,
                        approved_receipt_snapshot,
                        target_url=wire_url,
                        method=method_upper,
                    )
                    self._reserve_session_budget(
                        context,
                        fingerprint,
                        approved_receipt_snapshot["usd_value"],
                    )
                    session_budget_reserved = True
                    loop = asyncio.get_running_loop()
                    def _process_wrapper():
                        return self._process_payment(
                            parsed, headers, payload, method=method, url=wire_url,
                            _attempt_tracker=attempt_tracker,
                        )

                    payment_result = await loop.run_in_executor(None, _process_wrapper)
                    if inspect.isawaitable(payment_result):
                        payment_result = await payment_result
                    proof_ref, network_name, l402_report = payment_result
                    self._assert_approved_receipt_snapshot_unchanged(
                        parsed,
                        approved_receipt_snapshot,
                        target_url=wire_url,
                        method=method_upper,
                    )

                    credential_generated = True
                    canonical_requirement = json.loads(
                        approved_receipt_snapshot["canonical_snapshot_json"]
                    )
                    credential_only = (
                        parsed.scheme == "exact"
                        and canonical_requirement["rail"] == "x402"
                    )

                    payment_performed = not (
                        l402_report and not getattr(l402_report, "payment_performed", True)
                    )
                    if credential_only:
                        payment_performed = False
                    elif not payment_performed:
                        credential_reused = True
                        self._release_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "credential_reused")
                    else:
                        self._confirm_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "completed")
                        context._payment_executed = True

                    payment_completed = payment_performed and not credential_only
                    delta_usd = (
                        float(Decimal(approved_receipt_snapshot["usd_value"]))
                        if payment_performed
                        else 0.0
                    )

                    receipt = self._new_settlement_receipt(
                        parsed,
                        network_name,
                        proof_ref,
                        l402_report,
                        wire_url,
                        fingerprint,
                        approved_snapshot=approved_receipt_snapshot,
                        payment_performed=payment_performed,
                    )
                    self.last_receipt = receipt

                    if credential_only:
                        attempt_tracker.mark_irreversible()

                    next_result = await self._execute_detailed_async_internal(
                        method, url, payload, headers, _current_hop, _payment_retry_count + 1,
                        context=context, outcome_matcher=outcome_matcher,
                        _current_receipt=receipt, _fingerprint=fingerprint
                    )

                    if credential_only:
                        self._confirm_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "completed")
                        context._payment_executed = True
                        payment_performed = True
                        payment_completed = True
                        delta_usd = float(
                            Decimal(approved_receipt_snapshot["usd_value"])
                        )
                        receipt.payment_performed = True

                    next_result.settlement_receipt = receipt
                    next_result.used_scheme = receipt.scheme
                    next_result.used_asset = receipt.asset
                    next_result.verification_status = receipt.verification_status

                    if getattr(self, "evidence_repo", None):
                        record = PaymentEvidenceRecord(
                            session_id=context.session_id, correlation_id=context.correlation_id,
                            target_url=wire_url, method=method, scheme=receipt.scheme,
                            asset=receipt.asset, amount=receipt.settled_amount,
                            trust_decision=decision,
                            receipt_summary={"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status},
                            outcome=next_result.outcome,
                            session_spend_delta_usd=delta_usd,
                            session_budget_event="confirmed",
                            session_budget_operation_id=fingerprint,
                            session_budget_amount_usd=delta_usd,
                            delegate_source=getattr(l402_report, "delegate_source", "native") if l402_report else "native",
                            payment_hash=getattr(l402_report, "payment_hash", None) if l402_report else None,
                            fee_sats=getattr(l402_report, "fee_sats", None) if l402_report else None,
                            cached_token_used=getattr(l402_report, "cached_token_used", False) if l402_report else False,
                            payment_performed=getattr(l402_report, "payment_performed", True) if l402_report else True,
                            sponsored_access=getattr(self, "_last_sponsored_access_evidence", None),
                            sandbox=getattr(self, "_last_sandbox_evidence", None)
                        )
                        await self._export_evidence_best_effort_async(record, context)

                    return next_result

                except Exception as caught_error:
                    error_type = caught_error.__class__
                    irreversible_or_paid = (
                        (
                            attempt_tracker.irreversible_attempt_started
                            and not credential_reused
                        )
                        or payment_completed
                    )

                    reserve_delta = 0.0
                    if credential_reused:
                        self._release_session_budget(context, fingerprint)
                        self._update_payment_state(
                            context, fingerprint, "credential_reused"
                        )
                    elif (
                        credential_only
                        and credential_generated
                        and attempt_tracker.irreversible_attempt_started
                        and not payment_completed
                    ):
                        reserve_delta = float(
                            self._mark_session_budget_unknown(
                                context, fingerprint
                            )
                        )
                        self._update_payment_state(
                            context, fingerprint, "settlement_unknown"
                        )
                    elif payment_completed:
                        self._mark_known_settled_ambiguity(context, fingerprint)
                    elif attempt_tracker.irreversible_attempt_started:
                        reserve_delta = self._reserve_ambiguous_spend(
                            context,
                            fingerprint,
                            parsed,
                            approved_usd_value=(
                                approved_receipt_snapshot["usd_value"]
                                if approved_receipt_snapshot is not None
                                else None
                            ),
                        )
                        self._update_payment_state(context, fingerprint, "ambiguous")
                    elif session_budget_reserved:
                        self._release_session_budget(context, fingerprint)
                        self._update_payment_state(context, fingerprint, "validation_failed")
                    else:
                        self._update_payment_state(
                            context, fingerprint, "validation_failed"
                        )

                    if credential_reused:
                        final_err = "credential_delivery_failed"
                        deferred_error_type = PaymentExecutionError
                        deferred_error_message = final_err
                    elif irreversible_or_paid:
                        final_err = (
                            "settlement_unknown"
                            if credential_only and not payment_completed
                            else "ambiguous_payment_result"
                        )
                        deferred_error_type = PaymentExecutionError
                        deferred_error_message = f"Ambiguous payment error: {final_err}"
                    else:
                        final_err = "payment_validation_failed_before_irreversible_processing"
                        deferred_error_type = error_type
                        if isinstance(caught_error, PaymentExecutionError):
                            deferred_error_message = sanitize_error_msg(
                                str(caught_error)
                            )
                        else:
                            deferred_error_message = final_err

                    if getattr(self, "evidence_repo", None):
                        evidence_projection = approved_receipt_snapshot or {
                            "scheme": parsed.scheme,
                            "asset": parsed.asset,
                            "amount": parsed.amount,
                        }
                        record_kwargs = {
                            "session_id": context.session_id, "correlation_id": context.correlation_id,
                            "target_url": wire_url, "method": method,
                            "scheme": evidence_projection["scheme"],
                            "asset": evidence_projection["asset"],
                            "amount": evidence_projection["amount"],
                            "trust_decision": decision, "error_message": final_err,
                            "sponsored_access": getattr(self, "_last_sponsored_access_evidence", None),
                            "sandbox": getattr(self, "_last_sandbox_evidence", None)
                        }
                        if (
                            not attempt_tracker.irreversible_attempt_started
                            and not payment_completed
                        ):
                            record_kwargs["payment_performed"] = False
                            record_kwargs["session_spend_delta_usd"] = 0.0
                        if credential_only and not payment_completed:
                            record_kwargs["payment_performed"] = False
                        if payment_completed:
                            record_kwargs["session_spend_delta_usd"] = delta_usd
                            record_kwargs["session_budget_event"] = "confirmed"
                            record_kwargs["session_budget_operation_id"] = fingerprint
                            record_kwargs["session_budget_amount_usd"] = delta_usd
                        elif reserve_delta > 0:
                            record_kwargs["payment_performed"] = False
                            record_kwargs["session_spend_delta_usd"] = 0.0
                            record_kwargs["session_budget_event"] = "reserved"
                            record_kwargs["session_budget_operation_id"] = fingerprint
                            record_kwargs["session_budget_amount_usd"] = reserve_delta
                            if receipt is not None:
                                record_kwargs["receipt_summary"] = {
                                    "receipt_id": receipt.receipt_id,
                                    "verification_status": receipt.verification_status,
                                }
                        if payment_completed and receipt is not None:
                            record_kwargs["receipt_summary"] = {"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status}

                        deferred_error_record = PaymentEvidenceRecord(**record_kwargs)

                if deferred_error_record is not None:
                    await self._export_evidence_best_effort_async(
                        deferred_error_record, context
                    )
                if deferred_error_type is not None:
                    raise _new_sanitized_exception(
                        deferred_error_type, deferred_error_message
                    ) from None

            break

        if (
            _current_receipt is not None
            and _current_receipt.scheme == "exact"
            and not _current_receipt.payment_performed
        ):
            raise PaymentExecutionError(
                "Ambiguous payment error: exact credential retry did not "
                "receive a direct success response."
            )

        try:
            error_data = res.json()
        except Exception:
            error_data = {}

        next_action, source = self._resolve_next_action(error_data, res.headers)

        if self.auto_navigate and next_action:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()

            is_unsafe = next_method not in ["GET", "HEAD"]

            if is_unsafe and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")

            if next_url and next_method != "NONE":
                next_url, merged_headers, merged_payload, is_cross_origin = self._prepare_hateoas_navigation(
                    url, next_url, next_method, headers, next_action.suggested_headers,
                    payload, next_action.suggested_payload,
                    context.hints.get("allowed_hosts", []),
                    context=context, fingerprint=fingerprint,
                )
                _, next_wire_key = self._logical_and_wire_idempotency_key(
                    context, next_url
                )
                merged_headers["Idempotency-Key"] = next_wire_key

                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                next_result = await self._execute_detailed_async_internal(
                    next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=_current_receipt, _fingerprint=fingerprint
                )

                if getattr(self, "evidence_repo", None):
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, navigation_source=source, outcome=next_result.outcome,
                        sponsored_access=getattr(self, "_last_sponsored_access_evidence", None),
                        sandbox=getattr(self, "_last_sandbox_evidence", None)
                    )
                    await self._export_evidence_best_effort_async(record, context)
                return next_result

        error_msg = sanitize_error_msg(error_data.get('message', res.text) if res else "No response")
        status_c = res.status_code if res else 500
        raise PaymentExecutionError(f"API Error {status_c}: {error_msg}")

    async def aclose(self):
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    async def __aenter__(self):
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                follow_redirects=False, trust_env=False
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    def get_last_sandbox_corpus_candidate(self) -> Optional['SandboxCorpusCandidate']:
        return self.build_sandbox_corpus_candidate_from_last_evidence()

    def build_sandbox_corpus_candidate_from_last_evidence(self) -> Optional['SandboxCorpusCandidate']:
        ev = self.get_last_sandbox_evidence()
        if ev:
            from .evidence import build_sandbox_corpus_candidate
            return build_sandbox_corpus_candidate(ev)
        return None

class LnChurchClient(Payment402Client):
    def __init__(
        self,
        agent_id: Optional[str] = None,
        private_key: Optional[str] = None,
        svm_private_key: Optional[str] = None,
        svm_rpc_url: Optional[str] = None,
        ln_api_url: Optional[str] = None,
        ln_api_key: Optional[str] = None,
        ln_provider: str = "lnbits",
        base_url: str = "https://kari.mayim-mayim.com",
        evm_rpc_url: Optional[str] = None,
        auto_navigate: bool = True,
        max_hops: int = 3,
        allow_unsafe_navigate: bool = False,
        evm_signer: Optional[EVMSigner] = None,
        ln_adapter: Optional[LightningProvider] = None,
        solana_signer: Optional[SolanaSigner] = None,
        policy: Optional[PaymentPolicy] = None,
        *args,
        **kwargs
    ):
        derived_agent_id = agent_id
        if private_key and not agent_id:
            try:
                from eth_account import Account
                derived_agent_id = Account.from_key(private_key).address
            except Exception:
                try:
                    from solders.keypair import Keypair
                    derived_agent_id = str(Keypair.from_base58_string(private_key).pubkey())
                except Exception as e:
                    raise ValueError(
                        "Invalid private_key format. Could not parse as EVM hex or Solana Base58. "
                        f"Detailed error: {e}"
                    )
        else:
            derived_agent_id = agent_id or "Anonymous_Agent"

        try:
            super().__init__(
                private_key=private_key,
                svm_private_key=svm_private_key,
                svm_rpc_url=svm_rpc_url,
                ln_api_url=ln_api_url,
                ln_api_key=ln_api_key,
                ln_provider=ln_provider,
                base_url=base_url,
                evm_rpc_url=evm_rpc_url,
                auto_navigate=auto_navigate,
                max_hops=max_hops,
                allow_unsafe_navigate=allow_unsafe_navigate,
                evm_signer=evm_signer,
                ln_adapter=ln_adapter,
                solana_signer=solana_signer,
                policy=policy,
                *args,
                **kwargs
            )
        except ValueError as e:
            raise ValueError(f"Invalid private_key format. Details: {str(e)}") from e

        self.agent_id = derived_agent_id
        self.probe_token = None
        self.faucet_token = None
        self.grant_token = None

    def set_grant_token(self, token: str):
        self.grant_token = token

    def diagnose_grant(self, route: str = "/api/agent/omikuji", method: str = "POST") -> "GrantDiagnostics":
        from .grants import diagnose_grant_token
        return diagnose_grant_token(
            self.grant_token,
            agent_id=self.agent_id,
            base_url=self.base_url,
            route=route,
            method=method
        )

    def explain_grant(self, route: str = "/api/agent/omikuji", method: str = "POST") -> dict:
        diag = self.diagnose_grant(route=route, method=method)
        res = {
            "usable": diag.usable,
            "access_path": diag.access_path,
            "authorization_artifact": diag.authorization_artifact,
            "settlement_rail": diag.settlement_rail,
            "grant_jti": diag.grant_jti,
            "scope": {
                "routes": diag.scope_routes,
                "methods": diag.scope_methods
            },
            "recommended_action": diag.recommended_action,
            "note": "Local diagnostics only. Server-side validation is authoritative."
        }
        if diag.failure_class:
            res["failure_class"] = diag.failure_class
        if diag.reason:
            res["reason"] = diag.reason
        if diag.fallback_action:
            res["fallback_action"] = diag.fallback_action
        return res

    def has_valid_scoped_grant(self, target_path: str, method: str) -> bool:
        diag = self.diagnose_grant(route=target_path, method=method)
        self._last_grant_diagnostics = diag
        return diag.usable

    def _inject_telemetry(self, headers: Optional[dict]) -> dict:
        headers = dict(headers or {})
        headers["X-LN-Church-Agent-Version"] = SDK_VERSION
        if not any(k.lower() == "x-ln-church-request-id" for k in headers.keys()):
            headers["X-LN-Church-Request-Id"] = str(uuid.uuid4())
        return headers

    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        telemetry_headers = self._inject_telemetry(headers)
        return super().execute_request(method, endpoint_path, payload, telemetry_headers)

    async def execute_request_async(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        telemetry_headers = self._inject_telemetry(headers)
        return await super().execute_request_async(method, endpoint_path, payload, telemetry_headers)

    def _collect_execution_access_candidates(self, target_path: str, method: str, asset: str, scheme: str) -> List[_ExecutionAccessPlan]:
        candidates = []
        if self.has_valid_scoped_grant(target_path, method):
            candidates.append(_ExecutionAccessPlan(
                unlock=_ExecutionUnlock.ENTITLEMENT_PROOF,
                funding_policy=_FundingPolicy.FULLY_SPONSORED,
                entitlement_kind=_EntitlementKind.GRANT,
                settlement_scheme=scheme,
                settlement_asset=asset,
                selected_reason="Valid scoped grant token available."
            ))

        if self.faucet_token and target_path == "/api/agent/omikuji":
            candidates.append(_ExecutionAccessPlan(
                unlock=_ExecutionUnlock.ENTITLEMENT_PROOF,
                funding_policy=_FundingPolicy.FULLY_SPONSORED,
                entitlement_kind=_EntitlementKind.FAUCET,
                settlement_scheme=scheme,
                settlement_asset=asset,
                selected_reason="Legacy faucet token available for Omikuji."
            ))

        candidates.append(_ExecutionAccessPlan(
            unlock=_ExecutionUnlock.SETTLEMENT_PROOF,
            funding_policy=_FundingPolicy.SELF_FUNDED,
            entitlement_kind=None,
            settlement_scheme=scheme,
            settlement_asset=asset,
            selected_reason="Direct 402 settlement."
        ))

        return candidates

    def _select_execution_access_plan(self, candidates: List[_ExecutionAccessPlan]) -> _ExecutionAccessPlan:
        for kind in [_EntitlementKind.GRANT, _EntitlementKind.FAUCET]:
            for c in candidates:
                if c.entitlement_kind == kind:
                    return c
        for c in candidates:
            if c.unlock == _ExecutionUnlock.SETTLEMENT_PROOF:
                return c
        return candidates[-1]

    def _build_payment_override_from_plan(self, plan: _ExecutionAccessPlan) -> Optional[dict]:
        if plan.entitlement_kind == _EntitlementKind.GRANT:
            return {
                "type": "grant",
                "proof": self.grant_token,
                "asset": AssetType.GRANT_CREDIT.value
            }
        elif plan.entitlement_kind == _EntitlementKind.FAUCET:
            return {
                "type": "faucet",
                "proof": self.faucet_token,
                "asset": AssetType.FAUCET_CREDIT.value
            }
        return None

    def init_probe(self, **kwargs):
        payload = kwargs if kwargs else None
        res = self.execute_request("GET", f"/api/agent/probe?agentId={self.agent_id}&src=sdk", payload=payload)
        self.probe_token = res.get("capability_receipt", {}).get("token") or res.get("probe_token")
        print("[System] Probe Completed.")

    def claim_faucet_if_empty(self, **kwargs):
        try:
            payload = {"agentId": self.agent_id}
            payload.update(kwargs)
            res = self.execute_request("POST", "/api/agent/faucet", payload)
            self.faucet_token = res.get("grant_token")
            print("[System] Faucet Claimed.")
        except Exception as e:
            print(f"[System] Faucet skipped or failed: {str(e)}")

    def draw_omikuji(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> OmikujiResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        target_path = "/api/agent/omikuji"

        candidates = self._collect_execution_access_candidates(target_path, "POST", asset.value, target_scheme)
        plan = self._select_execution_access_plan(candidates)

        payload = {
            "agentId": self.agent_id,
            "clientType": "AI",
            "scheme": plan.settlement_scheme,
            "asset": plan.settlement_asset
        }

        override = self._build_payment_override_from_plan(plan)
        if override:
            payload["paymentOverride"] = override

        payload.update(kwargs)

        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        return OmikujiResponse(**self.execute_request("POST", target_path, payload, headers))

    def submit_confession(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None, **kwargs) -> ConfessionResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        payload.update(kwargs)
        return ConfessionResponse(**self.execute_request("POST", "/api/agent/confession", payload))

    def offer_hono(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> HonoResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value, "amount": amount}
        payload.update(kwargs)
        return HonoResponse(**self.execute_request("POST", "/api/agent/hono", payload))

    def issue_identity(self, **kwargs) -> AgentIdentity:
        payload = {"agentId": self.agent_id}
        payload.update(kwargs)
        res = self.execute_request("POST", "/api/agent/identity/issue", payload)
        return AgentIdentity(status=res["status"], public_profile_url=res["public_profile_url"], agent_id=self.agent_id)

    def resolve_identity(self, target_agent_id: str = None, **kwargs) -> AgentIdentity:
        target_id = target_agent_id or self.agent_id
        payload = kwargs if kwargs else None
        res = self.execute_request("GET", f"/api/agent/identity/{target_id}", payload=payload)
        return AgentIdentity(**res)

    def get_benchmark_overview(self, **kwargs) -> BenchmarkOverviewResponse:
        payload = kwargs if kwargs else None
        return BenchmarkOverviewResponse(**self.execute_request("GET", f"/api/agent/benchmark/{self.agent_id}", payload=payload))

    def compare_trial_performance(self, trial_id: str, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> CompareResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        payload.update(kwargs)
        return CompareResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload))

    def request_fast_pass_aggregate(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> AggregateResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        payload.update(kwargs)
        return AggregateResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{self.agent_id}/aggregate", payload))

    def submit_monzen_trace(self, target_url: str, invoice: str, preimage: Optional[str] = None, method: str = "POST", scheme: Optional[str] = None, **kwargs) -> MonzenTraceResponse:
        payload = {"agentId": self.agent_id, "targetUrl": target_url, "invoice": invoice, "method": method}
        if preimage: payload["preimage"] = preimage
        if scheme: payload["scheme"] = scheme
        payload.update(kwargs)
        res_dict = self.execute_request("POST", "/api/agent/monzen/trace", payload)
        return MonzenTraceResponse(**res_dict)

    def get_site_metrics(self, limit: int = 10, target_agent_id: Optional[str] = None, scheme: Optional[str] = None, **kwargs) -> MonzenMetricsResponse:
        params = {"limit": limit}
        if target_agent_id: params["agentId"] = target_agent_id
        if scheme: params["scheme"] = scheme
        params.update(kwargs)
        return MonzenMetricsResponse(**self.execute_request("GET", "/api/agent/monzen/metrics", payload=params))

    def download_monzen_graph(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> MonzenGraphResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        payload.update(kwargs)
        res = self.execute_request("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)

    async def init_probe_async(self, **kwargs):
        payload = kwargs if kwargs else None
        res = await self.execute_request_async("GET", f"/api/agent/probe?agentId={self.agent_id}&src=sdk_async", payload=payload)
        self.probe_token = res.get("capability_receipt", {}).get("token") or res.get("probe_token")
        print("[System ASYNC] Probe Completed.")

    async def claim_faucet_if_empty_async(self, **kwargs):
        try:
            payload = {"agentId": self.agent_id}
            payload.update(kwargs)
            res = await self.execute_request_async("POST", "/api/agent/faucet", payload)
            self.faucet_token = res.get("grant_token")
            print("[System ASYNC] Faucet Claimed.")
        except Exception as e:
            print(f"[System ASYNC] Faucet skipped or failed: {str(e)}")

    async def draw_omikuji_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> OmikujiResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        target_path = "/api/agent/omikuji"

        candidates = self._collect_execution_access_candidates(target_path, "POST", asset.value, target_scheme)
        plan = self._select_execution_access_plan(candidates)

        payload = {
            "agentId": self.agent_id,
            "clientType": "AI",
            "scheme": plan.settlement_scheme,
            "asset": plan.settlement_asset
        }

        override = self._build_payment_override_from_plan(plan)
        if override:
            payload["paymentOverride"] = override

        payload.update(kwargs)

        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        res = await self.execute_request_async("POST", target_path, payload, headers)
        return OmikujiResponse(**res)

    async def submit_confession_async(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None, **kwargs) -> ConfessionResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        payload.update(kwargs)
        res = await self.execute_request_async("POST", "/api/agent/confession", payload)
        return ConfessionResponse(**res)

    async def offer_hono_async(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> HonoResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value, "amount": amount}
        payload.update(kwargs)
        res = await self.execute_request_async("POST", "/api/agent/hono", payload)
        return HonoResponse(**res)

    async def issue_identity_async(self, **kwargs) -> AgentIdentity:
        payload = {"agentId": self.agent_id}
        payload.update(kwargs)
        res = await self.execute_request_async("POST", "/api/agent/identity/issue", payload)
        return AgentIdentity(status=res["status"], public_profile_url=res["public_profile_url"], agent_id=self.agent_id)

    async def resolve_identity_async(self, target_agent_id: str = None, **kwargs) -> AgentIdentity:
        target_id = target_agent_id or self.agent_id
        payload = kwargs if kwargs else None
        res = await self.execute_request_async("GET", f"/api/agent/identity/{target_id}", payload=payload)
        return AgentIdentity(**res)

    async def get_benchmark_overview_async(self, **kwargs) -> BenchmarkOverviewResponse:
        payload = kwargs if kwargs else None
        res = await self.execute_request_async("GET", f"/api/agent/benchmark/{self.agent_id}", payload=payload)
        return BenchmarkOverviewResponse(**res)

    async def compare_trial_performance_async(self, trial_id: str, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> CompareResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        payload.update(kwargs)
        res = await self.execute_request_async("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload)
        return CompareResponse(**res)

    async def request_fast_pass_aggregate_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> AggregateResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        payload.update(kwargs)
        res = await self.execute_request_async("POST", f"/api/agent/benchmark/trials/{self.agent_id}/aggregate", payload)
        return AggregateResponse(**res)

    async def submit_monzen_trace_async(self, target_url: str, invoice: str, preimage: Optional[str] = None, method: str = "POST", scheme: Optional[str] = None, **kwargs) -> MonzenTraceResponse:
        payload = {"agentId": self.agent_id, "targetUrl": target_url, "invoice": invoice, "method": method}
        if preimage: payload["preimage"] = preimage
        if scheme: payload["scheme"] = scheme
        payload.update(kwargs)
        res_dict = await self.execute_request_async("POST", "/api/agent/monzen/trace", payload)
        return MonzenTraceResponse(**res_dict)

    async def get_site_metrics_async(self, limit: int = 10, target_agent_id: Optional[str] = None, scheme: Optional[str] = None, **kwargs) -> MonzenMetricsResponse:
        params = {"limit": limit}
        if target_agent_id: params["agentId"] = target_agent_id
        if scheme: params["scheme"] = scheme
        params.update(kwargs)
        res = await self.execute_request_async("GET", "/api/agent/monzen/metrics", payload=params)
        return MonzenMetricsResponse(**res)

    async def download_monzen_graph_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None, **kwargs) -> MonzenGraphResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        payload.update(kwargs)
        res = await self.execute_request_async("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)

    def run_l402_sandbox_harness(self) -> "InteropRunResult":
        import json
        import hashlib
        import re
        from .models import InteropRunResult

        basic_path = "/api/agent/sandbox/l402/basic"
        report_path = "/api/agent/sandbox/interop/report"

        exec_result = self.execute_detailed("GET", basic_path)
        resp = exec_result.response

        meta = resp.get("meta", {})
        run_id = meta.get("run_id", "")
        scenario_id = meta.get("scenario_id", "")
        expected_hash = meta.get("canonical_hash_expected", "")
        interop_token = meta.get("interop_token", "")

        deterministic_payload = {
            "message": resp.get("message"),
            "scenario": resp.get("scenario"),
            "contract": resp.get("contract"),
            "verifiable": resp.get("verifiable")
        }
        json_str = json.dumps(deterministic_payload, separators=(',', ':'))
        observed_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        receipt = exec_result.settlement_receipt
        payment_performed = receipt.payment_performed if receipt else True
        cached_token_used = receipt.cached_token_used if receipt else False
        delegate_source = receipt.delegate_source if receipt else "native"
        executor_mode = "ln-church-agent-native" if delegate_source == "native" else delegate_source

        auth_scheme = receipt.scheme if receipt and receipt.scheme else (exec_result.used_scheme or "L402")

        payment_receipt_present = bool(
            receipt
            and getattr(receipt, "present", False)
            and getattr(receipt, "source", None) == AttestationSource.SERVER_JWS
        )

        report_payload = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "canonical_hash_expected": expected_hash,
            "canonical_hash_observed": observed_hash,
            "executor_mode": executor_mode,
            "delegate_source": delegate_source,
            "cached_token_used": cached_token_used,
            "payment_performed": payment_performed,
            "fee_sats": receipt.fee_sats if receipt else 0,
            "sdk_version": SDK_VERSION,
            "interop_token": interop_token,
            "comparison_class": "production_like",
            "test_mode": "normal",
            "rail": "L402",
            "payment_intent": "charge",
            "authorization_scheme": auth_scheme,
            "payment_receipt_present": payment_receipt_present
        }

        report_resp = {}
        status_code = 500
        accepted = False
        try:
            report_exec = self.execute_detailed("POST", report_path, payload=report_payload)
            report_resp = report_exec.response
            status_code = 200
            accepted = report_resp.get("status") == "success"
        except Exception as e:
            m = re.search(r"API Error (\d+):", str(e))
            if m:
                status_code = int(m.group(1))
            report_resp = {"error": str(e)}

        return InteropRunResult(
            ok=accepted and (expected_hash == observed_hash),
            target_url=exec_result.final_url,
            run_id=run_id,
            scenario_id=scenario_id,
            executor_mode=executor_mode,
            delegate_source=delegate_source,
            canonical_hash_expected=expected_hash,
            canonical_hash_observed=observed_hash,
            canonical_hash_matched=(expected_hash == observed_hash),
            report_status_code=status_code,
            report_accepted=accepted,
            payment_performed=payment_performed,
            cached_token_used=cached_token_used,
            receipt_id=receipt.receipt_id if receipt else None,
            raw_report_response=report_resp
        )

    async def run_l402_sandbox_harness_async(self) -> "InteropRunResult":
        import json
        import hashlib
        import re
        from .models import InteropRunResult

        basic_path = "/api/agent/sandbox/l402/basic"
        report_path = "/api/agent/sandbox/interop/report"

        exec_result = await self.execute_detailed_async("GET", basic_path)
        resp = exec_result.response

        meta = resp.get("meta", {})
        run_id = meta.get("run_id", "")
        scenario_id = meta.get("scenario_id", "")
        expected_hash = meta.get("canonical_hash_expected", "")
        interop_token = meta.get("interop_token", "")

        deterministic_payload = {
            "message": resp.get("message"),
            "scenario": resp.get("scenario"),
            "contract": resp.get("contract"),
            "verifiable": resp.get("verifiable")
        }
        json_str = json.dumps(deterministic_payload, separators=(',', ':'))
        observed_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        receipt = exec_result.settlement_receipt
        payment_performed = receipt.payment_performed if receipt else True
        cached_token_used = receipt.cached_token_used if receipt else False
        delegate_source = receipt.delegate_source if receipt else "native"
        executor_mode = "ln-church-agent-native" if delegate_source == "native" else delegate_source

        auth_scheme = receipt.scheme if receipt and receipt.scheme else (exec_result.used_scheme or "L402")

        payment_receipt_present = bool(
            receipt
            and getattr(receipt, "present", False)
            and getattr(receipt, "source", None) == AttestationSource.SERVER_JWS
        )

        report_payload = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "canonical_hash_expected": expected_hash,
            "canonical_hash_observed": observed_hash,
            "executor_mode": executor_mode,
            "delegate_source": delegate_source,
            "cached_token_used": cached_token_used,
            "payment_performed": payment_performed,
            "fee_sats": receipt.fee_sats if receipt else 0,
            "sdk_version": SDK_VERSION,
            "interop_token": interop_token,
            "comparison_class": "production_like",
            "test_mode": "normal",
            "rail": "L402",
            "payment_intent": "charge",
            "authorization_scheme": auth_scheme,
            "payment_receipt_present": payment_receipt_present
        }

        report_resp = {}
        status_code = 500
        accepted = False
        try:
            report_exec = await self.execute_detailed_async("POST", report_path, payload=report_payload)
            report_resp = report_exec.response
            status_code = 200
            accepted = report_resp.get("status") == "success"
        except Exception as e:
            m = re.search(r"API Error (\d+):", str(e))
            if m:
                status_code = int(m.group(1))
            report_resp = {"error": str(e)}

        return InteropRunResult(
            ok=accepted and (expected_hash == observed_hash),
            target_url=exec_result.final_url,
            run_id=run_id,
            scenario_id=scenario_id,
            executor_mode=executor_mode,
            delegate_source=delegate_source,
            canonical_hash_expected=expected_hash,
            canonical_hash_observed=observed_hash,
            canonical_hash_matched=(expected_hash == observed_hash),
            report_status_code=status_code,
            report_accepted=accepted,
            payment_performed=payment_performed,
            cached_token_used=cached_token_used,
            receipt_id=receipt.receipt_id if receipt else None,
            raw_report_response=report_resp
        )

    def run_mpp_charge_sandbox_harness(self) -> "InteropRunResult":
        import json
        import hashlib
        import re
        from .models import InteropRunResult

        basic_path = "/api/agent/sandbox/mpp/charge/basic"
        report_path = "/api/agent/sandbox/interop/report"

        exec_result = None
        failure_reason = None
        error_msg = ""

        try:
            exec_result = self.execute_detailed("GET", basic_path)
            resp = exec_result.response
        except Exception as e:
            error_msg = str(e)
            if "mpp_session_not_supported_yet" in error_msg:
                failure_reason = "mpp_session_not_supported_yet"
            else:
                failure_reason = "payment_failed"
            resp = {}

        meta = resp.get("meta", {})
        run_id = meta.get("run_id", "")
        scenario_id = meta.get("scenario_id", "")
        expected_hash = meta.get("canonical_hash_expected", "")
        interop_token = meta.get("interop_token", "")

        observed_hash = ""
        if not failure_reason:
            deterministic_payload = {
                "message": resp.get("message"),
                "scenario": resp.get("scenario"),
                "contract": resp.get("contract"),
                "verifiable": resp.get("verifiable")
            }
            json_str = json.dumps(deterministic_payload, separators=(',', ':'))
            observed_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        parsed = getattr(self, "_last_parsed_challenge", None)

        receipt = exec_result.settlement_receipt if exec_result else None
        payment_performed = receipt.payment_performed if receipt else (failure_reason is None)
        cached_token_used = receipt.cached_token_used if receipt else False
        executor_mode = "ln-church-agent-native"

        if receipt and receipt.scheme:
            auth_scheme = receipt.scheme
        elif exec_result and exec_result.used_scheme:
            auth_scheme = exec_result.used_scheme
        elif parsed and parsed.scheme:
            auth_scheme = parsed.scheme
        else:
            auth_scheme = "Payment"

        credential_shape = "legacy-preimage" if receipt else "unsupported-payment-auth-json"

        p_intent = "charge"
        p_method = "lightning"
        p_shape = "unknown"
        p_b64 = False
        p_decoded = False

        if parsed:
            if getattr(parsed, "payment_intent", "unknown") != "unknown":
                p_intent = parsed.payment_intent
            if getattr(parsed, "payment_method", "unknown") != "unknown":
                p_method = parsed.payment_method
            p_shape = getattr(parsed, "draft_shape", "unknown")
            p_b64 = getattr(parsed, "request_b64_present", False)
            p_decoded = getattr(parsed, "decoded_request_valid", False)

        payment_receipt_present = bool(
            receipt
            and getattr(receipt, "present", False)
            and getattr(receipt, "source", None) == AttestationSource.SERVER_JWS
        )

        report_payload = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "canonical_hash_expected": expected_hash,
            "canonical_hash_observed": observed_hash,
            "executor_mode": executor_mode,
            "delegate_source": "native",
            "cached_token_used": cached_token_used,
            "payment_performed": payment_performed,
            "fee_sats": receipt.fee_sats if receipt else 0,
            "sdk_version": SDK_VERSION,
            "interop_token": interop_token,
            "comparison_class": "production_like",
            "test_mode": "normal",
            "rail": "MPP",
            "payment_intent": p_intent,
            "payment_method": p_method,
            "authorization_scheme": auth_scheme,
            "draft_shape": p_shape,
            "request_b64_present": p_b64,
            "decoded_request_valid": p_decoded,
            "credential_shape": credential_shape,
            "payment_receipt_present": payment_receipt_present,
            "failure_reason": failure_reason
        }

        report_resp = {}
        status_code = 500
        accepted = False
        try:
            report_exec = self.execute_detailed("POST", report_path, payload=report_payload)
            report_resp = report_exec.response
            status_code = 200
            accepted = report_resp.get("status") == "success"
        except Exception as e:
            m = re.search(r"API Error (\d+):", str(e))
            if m: status_code = int(m.group(1))
            report_resp = {"error": str(e)}

        ok_status = accepted and (expected_hash == observed_hash) if not failure_reason else False

        return InteropRunResult(
            ok=ok_status,
            target_url=exec_result.final_url if exec_result else basic_path,
            run_id=run_id,
            scenario_id=scenario_id,
            executor_mode=executor_mode,
            delegate_source="native",
            canonical_hash_expected=expected_hash,
            canonical_hash_observed=observed_hash,
            canonical_hash_matched=(expected_hash == observed_hash) if expected_hash else False,
            report_status_code=status_code,
            report_accepted=accepted,
            payment_performed=payment_performed,
            cached_token_used=cached_token_used,
            receipt_id=receipt.receipt_id if receipt else None,
            raw_report_response=report_resp
        )

    async def run_mpp_charge_sandbox_harness_async(self) -> "InteropRunResult":
        import json
        import hashlib
        import re
        from .models import InteropRunResult

        basic_path = "/api/agent/sandbox/mpp/charge/basic"
        report_path = "/api/agent/sandbox/interop/report"

        exec_result = None
        failure_reason = None
        error_msg = ""

        try:
            exec_result = await self.execute_detailed_async("GET", basic_path)
            resp = exec_result.response
        except Exception as e:
            error_msg = str(e)
            if "mpp_session_not_supported_yet" in error_msg:
                failure_reason = "mpp_session_not_supported_yet"
            else:
                failure_reason = "payment_failed"
            resp = {}

        meta = resp.get("meta", {})
        run_id = meta.get("run_id", "")
        scenario_id = meta.get("scenario_id", "")
        expected_hash = meta.get("canonical_hash_expected", "")
        interop_token = meta.get("interop_token", "")

        observed_hash = ""
        if not failure_reason:
            deterministic_payload = {
                "message": resp.get("message"),
                "scenario": resp.get("scenario"),
                "contract": resp.get("contract"),
                "verifiable": resp.get("verifiable")
            }
            json_str = json.dumps(deterministic_payload, separators=(',', ':'))
            observed_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        parsed = getattr(self, "_last_parsed_challenge", None)

        receipt = exec_result.settlement_receipt if exec_result else None
        payment_performed = receipt.payment_performed if receipt else (failure_reason is None)
        cached_token_used = receipt.cached_token_used if receipt else False
        executor_mode = "ln-church-agent-native"

        if receipt and receipt.scheme:
            auth_scheme = receipt.scheme
        elif exec_result and exec_result.used_scheme:
            auth_scheme = exec_result.used_scheme
        elif parsed and parsed.scheme:
            auth_scheme = parsed.scheme
        else:
            auth_scheme = "Payment"

        credential_shape = "legacy-preimage" if receipt else "unsupported-payment-auth-json"

        p_intent = "charge"
        p_method = "lightning"
        p_shape = "unknown"
        p_b64 = False
        p_decoded = False

        if parsed:
            if getattr(parsed, "payment_intent", "unknown") != "unknown":
                p_intent = parsed.payment_intent
            if getattr(parsed, "payment_method", "unknown") != "unknown":
                p_method = parsed.payment_method
            p_shape = getattr(parsed, "draft_shape", "unknown")
            p_b64 = getattr(parsed, "request_b64_present", False)
            p_decoded = getattr(parsed, "decoded_request_valid", False)

        payment_receipt_present = bool(
            receipt
            and getattr(receipt, "present", False)
            and getattr(receipt, "source", None) == AttestationSource.SERVER_JWS
        )

        report_payload = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "canonical_hash_expected": expected_hash,
            "canonical_hash_observed": observed_hash,
            "executor_mode": executor_mode,
            "delegate_source": "native",
            "cached_token_used": cached_token_used,
            "payment_performed": payment_performed,
            "fee_sats": receipt.fee_sats if receipt else 0,
            "sdk_version": SDK_VERSION,
            "interop_token": interop_token,
            "comparison_class": "production_like",
            "test_mode": "normal",
            "rail": "MPP",
            "payment_intent": p_intent,
            "payment_method": p_method,
            "authorization_scheme": auth_scheme,
            "draft_shape": p_shape,
            "request_b64_present": p_b64,
            "decoded_request_valid": p_decoded,
            "credential_shape": credential_shape,
            "payment_receipt_present": payment_receipt_present,
            "failure_reason": failure_reason
        }

        report_resp = {}
        status_code = 500
        accepted = False
        try:
            report_exec = await self.execute_detailed_async("POST", report_path, payload=report_payload)
            report_resp = report_exec.response
            status_code = 200
            accepted = report_resp.get("status") == "success"
        except Exception as e:
            m = re.search(r"API Error (\d+):", str(e))
            if m: status_code = int(m.group(1))
            report_resp = {"error": str(e)}

        ok_status = accepted and (expected_hash == observed_hash) if not failure_reason else False

        return InteropRunResult(
            ok=ok_status,
            target_url=exec_result.final_url if exec_result else basic_path,
            run_id=run_id,
            scenario_id=scenario_id,
            executor_mode=executor_mode,
            delegate_source="native",
            canonical_hash_expected=expected_hash,
            canonical_hash_observed=observed_hash,
            canonical_hash_matched=(expected_hash == observed_hash) if expected_hash else False,
            report_status_code=status_code,
            report_accepted=accepted,
            payment_performed=payment_performed,
            cached_token_used=cached_token_used,
            receipt_id=receipt.receipt_id if receipt else None,
            raw_report_response=report_resp
        )

    def run_corpus_replay(
        self,
        corpus_id: str,
        server_base_url: Optional[str] = None,
        *,
        dry_run: bool = True,
    ) -> "CorpusReplayResult":
        """
        Agent-side dry-run validation of a Server Synthetic Corpus Replay.
        Reads the replay descriptor and attempts to parse the synthetic challenge,
        comparing the agent's interpreted behavior against the corpus expected behavior.
        """
        if not dry_run:
            raise NotImplementedError("Real payment execution for corpus replay is not supported yet. dry_run must be True.")

        import requests
        from .models import CorpusReplayResult

        base = (server_base_url or self.base_url).rstrip('/')
        descriptor_url = f"{base}/api/agent/benchmark/replay/{corpus_id}"
        headers = {"User-Agent": CUSTOM_USER_AGENT}

        try:
            res_desc = requests.get(descriptor_url, headers=headers)
        except Exception as e:
            return CorpusReplayResult(
                ok=False, corpus_id=corpus_id, replay_type="unknown", expected_action="unknown",
                observed_action="unknown", failure_reason=f"Descriptor fetch failed: {str(e)}"
            )

        if res_desc.status_code != 200:
            return CorpusReplayResult(
                ok=False, corpus_id=corpus_id, replay_type="unknown", expected_action="unknown",
                observed_action="unknown", failure_reason=f"Descriptor fetch failed with status {res_desc.status_code}"
            )

        try:
            desc_data = res_desc.json()
        except Exception as e:
            return CorpusReplayResult(
                ok=False, corpus_id=corpus_id, replay_type="unknown", expected_action="unknown",
                observed_action="unknown", failure_reason=f"Descriptor JSON parse failed: {str(e)}"
            )

        replay_type = desc_data.get("replay_type", "unknown")
        schema_version = desc_data.get("schema_version")
        source_obs_id = desc_data.get("source_observation_id")
        desc_expected = desc_data.get("expected_client_behavior", {}).get("action", "unknown")

        challenge_path = desc_data.get("endpoints", {}).get("challenge")
        if not challenge_path:
            return CorpusReplayResult(
                ok=False, corpus_id=corpus_id, replay_type=replay_type, expected_action=desc_expected,
                observed_action="unknown", descriptor_schema_version=schema_version, source_observation_id=source_obs_id,
                raw_descriptor=desc_data, failure_reason="No challenge endpoint in descriptor"
            )

        challenge_url = challenge_path if challenge_path.startswith("http") else f"{base}{challenge_path}"

        try:
            res_chal = requests.get(challenge_url, headers=headers)
        except Exception as e:
            return CorpusReplayResult(
                ok=False, corpus_id=corpus_id, replay_type=replay_type, expected_action=desc_expected,
                observed_action="unknown", descriptor_schema_version=schema_version, source_observation_id=source_obs_id,
                raw_descriptor=desc_data, failure_reason=f"Challenge fetch failed: {str(e)}"
            )

        try:
            chal_data = res_chal.json()
        except Exception:
            chal_data = {}

        body_expected = chal_data.get("expected_client_behavior", {}).get("action")
        final_expected_action = body_expected or desc_expected

        observed_action = "unknown"
        failure_reason = None
        parsed_scheme, parsed_rail, parsed_intent, parsed_shape = None, None, None, None

        def _parse_challenge_from_requests_response(req_res):
            import httpx
            try:
                content = req_res.content
            except Exception:
                content = b""

            dummy_httpx_res = httpx.Response(
                status_code=req_res.status_code,
                headers=req_res.headers,
                content=content,
                request=httpx.Request("GET", req_res.url)
            )
            return self._parse_challenge(dummy_httpx_res)

        parsed_challenge = None
        parse_error = None
        if res_chal.status_code in (402, 401, 403):
            try:
                parsed_challenge = _parse_challenge_from_requests_response(res_chal)
                parsed_scheme = getattr(parsed_challenge, "scheme", None)
                parsed_intent = getattr(parsed_challenge, "payment_intent", None)
                parsed_shape = getattr(parsed_challenge, "draft_shape", None)
                parsed_rail = parsed_scheme
            except Exception as e:
                parse_error = str(e)

        if final_expected_action == "stop_safely":
            observed_action = "stop_safely"
        elif final_expected_action == "reject_invalid" or res_chal.status_code in (400, 422):
            observed_action = "reject_invalid"
        elif final_expected_action == "observe_only":
            observed_action = "observe_only"
            if parse_error:
                failure_reason = f"Parser failed (tolerated for observe_only): {parse_error}"
        elif final_expected_action == "pay_and_verify":
            if res_chal.status_code == 402 and parsed_challenge:
                observed_action = "pay_and_verify"
            else:
                observed_action = "unknown"
                failure_reason = parse_error or f"Expected 402 and valid challenge, got {res_chal.status_code}"

        ok = (final_expected_action == observed_action) and not (final_expected_action == "pay_and_verify" and parsed_challenge is None)

        return CorpusReplayResult(
            ok=ok,
            corpus_id=corpus_id,
            replay_type=replay_type,
            expected_action=final_expected_action,
            observed_action=observed_action,
            challenge_status_code=res_chal.status_code,
            descriptor_schema_version=schema_version,
            source_observation_id=source_obs_id,
            parsed_scheme=parsed_scheme,
            parsed_rail=parsed_rail,
            parsed_payment_intent=parsed_intent,
            parsed_draft_shape=parsed_shape,
            failure_reason=failure_reason,
            raw_descriptor=desc_data,
            raw_challenge_body=chal_data
        )

    async def run_corpus_replay_async(
        self,
        corpus_id: str,
        server_base_url: Optional[str] = None,
        *,
        dry_run: bool = True,
    ) -> "CorpusReplayResult":
        """Async version of run_corpus_replay"""
        if not dry_run:
            raise NotImplementedError("Real payment execution for corpus replay is not supported yet. dry_run must be True.")

        import httpx
        from .models import CorpusReplayResult

        base = (server_base_url or self.base_url).rstrip('/')
        descriptor_url = f"{base}/api/agent/benchmark/replay/{corpus_id}"
        headers = {"User-Agent": CUSTOM_USER_AGENT}

        async with httpx.AsyncClient(follow_redirects=True) as client:
            try:
                res_desc = await client.get(descriptor_url, headers=headers)
            except Exception as e:
                return CorpusReplayResult(ok=False, corpus_id=corpus_id, replay_type="unknown", expected_action="unknown", observed_action="unknown", failure_reason=f"Descriptor fetch failed: {str(e)}")

            if res_desc.status_code != 200:
                return CorpusReplayResult(ok=False, corpus_id=corpus_id, replay_type="unknown", expected_action="unknown", observed_action="unknown", failure_reason=f"Descriptor fetch failed with status {res_desc.status_code}")

            try:
                desc_data = res_desc.json()
            except Exception as e:
                return CorpusReplayResult(ok=False, corpus_id=corpus_id, replay_type="unknown", expected_action="unknown", observed_action="unknown", failure_reason=f"Descriptor JSON parse failed: {str(e)}")

            replay_type = desc_data.get("replay_type", "unknown")
            schema_version = desc_data.get("schema_version")
            source_obs_id = desc_data.get("source_observation_id")
            desc_expected = desc_data.get("expected_client_behavior", {}).get("action", "unknown")

            challenge_path = desc_data.get("endpoints", {}).get("challenge")
            if not challenge_path:
                return CorpusReplayResult(ok=False, corpus_id=corpus_id, replay_type=replay_type, expected_action=desc_expected, observed_action="unknown", descriptor_schema_version=schema_version, source_observation_id=source_obs_id, raw_descriptor=desc_data, failure_reason="No challenge endpoint in descriptor")

            challenge_url = challenge_path if challenge_path.startswith("http") else f"{base}{challenge_path}"

            try:
                res_chal = await client.get(challenge_url, headers=headers)
            except Exception as e:
                return CorpusReplayResult(ok=False, corpus_id=corpus_id, replay_type=replay_type, expected_action=desc_expected, observed_action="unknown", descriptor_schema_version=schema_version, source_observation_id=source_obs_id, raw_descriptor=desc_data, failure_reason=f"Challenge fetch failed: {str(e)}")

            try:
                chal_data = res_chal.json()
            except Exception:
                chal_data = {}

            body_expected = chal_data.get("expected_client_behavior", {}).get("action")
            final_expected_action = body_expected or desc_expected
            observed_action = "unknown"
            failure_reason = None
            parsed_scheme, parsed_rail, parsed_intent, parsed_shape = None, None, None, None

            parsed_challenge = None
            parse_error = None
            if res_chal.status_code in (402, 401, 403):
                try:
                    parsed_challenge = self._parse_challenge(res_chal)
                    parsed_scheme = getattr(parsed_challenge, "scheme", None)
                    parsed_intent = getattr(parsed_challenge, "payment_intent", None)
                    parsed_shape = getattr(parsed_challenge, "draft_shape", None)
                    parsed_rail = parsed_scheme
                except Exception as e:
                    parse_error = str(e)

            if final_expected_action == "stop_safely":
                observed_action = "stop_safely"
            elif final_expected_action == "reject_invalid" or res_chal.status_code in (400, 422):
                observed_action = "reject_invalid"
            elif final_expected_action == "observe_only":
                observed_action = "observe_only"
                if parse_error: failure_reason = f"Parser failed: {parse_error}"
            elif final_expected_action == "pay_and_verify":
                if res_chal.status_code == 402 and parsed_challenge:
                    observed_action = "pay_and_verify"
                else:
                    observed_action = "unknown"
                    failure_reason = parse_error or f"Expected 402, got {res_chal.status_code}"

            ok = (final_expected_action == observed_action) and not (final_expected_action == "pay_and_verify" and parsed_challenge is None)

            return CorpusReplayResult(
                ok=ok, corpus_id=corpus_id, replay_type=replay_type, expected_action=final_expected_action,
                observed_action=observed_action, challenge_status_code=res_chal.status_code,
                descriptor_schema_version=schema_version, source_observation_id=source_obs_id,
                parsed_scheme=parsed_scheme, parsed_rail=parsed_rail, parsed_payment_intent=parsed_intent,
                parsed_draft_shape=parsed_shape, failure_reason=failure_reason,
                raw_descriptor=desc_data, raw_challenge_body=chal_data
            )

    def run_external_protocol_verification(
        self, target_url: str, scenario_id: str = "external_verification_v1", debug: bool = False
    ) -> "ExternalProtocolRunResult":
        import time, re
        from .models import ExternalProtocolRunResult

        logs = []
        def dlog(msg):
            if debug: print(f"🔍 [DEBUG] {msg}")
            logs.append(msg)

        start_time = time.time()
        stage = "init"
        error_reason = None
        resp_data = None
        status_code = 500
        receipt = None
        origin = "unknown"
        upstream_host = None

        is_get = True
        use_delegate = (
            self.prefer_lightninglabs_l402 and
            _netloc_is_allowlisted(target_url, self.l402_delegate_allowed_hosts)
        )
        delegate_source = "lightninglabs-delegated" if use_delegate else "native"
        executor_mode = delegate_source if use_delegate else "ln-church-agent-native"

        dlog(f"Target: {target_url} | Mode: {executor_mode} | Delegate: {use_delegate}")
        if self.ln_adapter:
            masked_url = re.sub(r'://.*?@', '://[redacted]@', getattr(self.ln_adapter, 'api_url', 'unknown'))
            dlog(f"Payment Backend: {masked_url}")

        try:
            stage = "challenge_fetch"
            dlog("Step 1: Fetching 402 challenge...")

            exec_result = self.execute_detailed("GET", target_url)

            stage = "response_shape_check"
            resp_data = exec_result.response
            receipt = exec_result.settlement_receipt
            status_code = 200
            dlog("Step 2: Successfully received 200 OK after payment.")

        except Exception as e:
            error_reason = str(e)
            if "LNBits Payment Failed" in error_reason:
                origin = "payment_backend"
                stage = "payment_initiation"
            elif "initiated but not settled" in error_reason:
                origin = "payment_backend"
                stage = "payment_settlement_check"
            elif "402 challenge" in error_reason:
                origin = "target_endpoint"
                stage = "challenge_parse"

            m_code = re.search(r"Error code (\d+)", error_reason)
            if m_code: status_code = int(m_code.group(1))

            m_host = re.search(r"host-status.*?>(.*?)</span>", error_reason, re.S)
            if m_host:
                upstream_host = re.sub('<[^>]*>', '', m_host.group(1)).strip()
                dlog(f"Identified failing upstream host: {upstream_host}")

        latency_ms = int((time.time() - start_time) * 1000)

        response_shape_ok = False
        if resp_data:
            response_shape_ok = True
            excerpt = str(resp_data)[:200]
        else:
            excerpt = ""

        return ExternalProtocolRunResult(
            ok=(status_code == 200 and response_shape_ok),
            target_url=target_url,
            scenario_id=scenario_id,
            executor_mode=executor_mode,
            delegate_source=delegate_source,
            status_code_after_payment=status_code,
            payment_performed=receipt.payment_performed if receipt else (origin == "payment_backend"),
            cached_token_used=receipt.cached_token_used if receipt else False,
            receipt_id=receipt.receipt_id if receipt else None,
            latency_ms=latency_ms,
            response_shape_ok=response_shape_ok,
            response_excerpt=excerpt,
            protocol_success=(status_code == 200),
            schema_check_reason="Valid JSON" if response_shape_ok else "No response data",
            error_stage=stage if status_code != 200 else None,
            error_reason=error_reason,
            suspected_failure_origin=origin,
            upstream_status_code=status_code if status_code != 200 else None,
            upstream_host_excerpt=upstream_host,
            debug_logs=logs
        )

    async def run_external_protocol_verification_async(
        self, target_url: str, scenario_id: str = "external_verification_v1", debug: bool = False
    ) -> "ExternalProtocolRunResult":
        import time, re
        from .models import ExternalProtocolRunResult

        logs = []
        def dlog(msg):
            if debug: print(f"🔍 [DEBUG ASYNC] {msg}")
            logs.append(msg)

        start_time = time.time()
        stage = "init"
        error_reason = None
        resp_data = None
        status_code = 500
        receipt = None
        origin = "unknown"
        upstream_host = None

        use_delegate = (
            self.prefer_lightninglabs_l402 and
            _netloc_is_allowlisted(target_url, self.l402_delegate_allowed_hosts)
        )
        delegate_source = "lightninglabs-delegated" if use_delegate else "native"
        executor_mode = delegate_source if use_delegate else "ln-church-agent-native"

        dlog(f"Target: {target_url} | Mode: {executor_mode} | Delegate: {use_delegate}")
        if self.ln_adapter:
            masked_url = re.sub(r'://.*?@', '://[redacted]@', getattr(self.ln_adapter, 'api_url', 'unknown'))
            dlog(f"Payment Backend: {masked_url}")

        try:
            stage = "challenge_fetch"
            dlog("Step 1: Fetching 402 challenge (Async)...")

            exec_result = await self.execute_detailed_async("GET", target_url)

            stage = "response_shape_check"
            resp_data = exec_result.response
            receipt = exec_result.settlement_receipt
            status_code = 200
            dlog("Step 2: Successfully received 200 OK after payment (Async).")

        except Exception as e:
            error_reason = str(e)
            if "LNBits Payment Failed" in error_reason:
                origin = "payment_backend"
                stage = "payment_initiation"
            elif "initiated but not settled" in error_reason:
                origin = "payment_backend"
                stage = "payment_settlement_check"
            elif "402 challenge" in error_reason:
                origin = "target_endpoint"
                stage = "challenge_parse"

            m_code = re.search(r"Error code (\d+)", error_reason)
            if m_code: status_code = int(m_code.group(1))

            m_host = re.search(r"host-status.*?>(.*?)</span>", error_reason, re.S)
            if m_host:
                upstream_host = re.sub('<[^>]*>', '', m_host.group(1)).strip()
                dlog(f"Identified failing upstream host: {upstream_host}")

        latency_ms = int((time.time() - start_time) * 1000)

        response_shape_ok = False
        if resp_data:
            response_shape_ok = True
            excerpt = str(resp_data)[:200]
        else:
            excerpt = ""

        return ExternalProtocolRunResult(
            ok=(status_code == 200 and response_shape_ok),
            target_url=target_url,
            scenario_id=scenario_id,
            executor_mode=executor_mode,
            delegate_source=delegate_source,
            status_code_after_payment=status_code,
            payment_performed=receipt.payment_performed if receipt else (origin == "payment_backend"),
            cached_token_used=receipt.cached_token_used if receipt else False,
            receipt_id=receipt.receipt_id if receipt else None,
            latency_ms=latency_ms,
            response_shape_ok=response_shape_ok,
            response_excerpt=excerpt,
            protocol_success=(status_code == 200),
            schema_check_reason="Valid JSON" if response_shape_ok else "No response data",
            error_stage=stage if status_code != 200 else None,
            error_reason=error_reason,
            suspected_failure_origin=origin,
            upstream_status_code=status_code if status_code != 200 else None,
            upstream_host_excerpt=upstream_host,
            debug_logs=logs
        )

    # ==========================================
    # Phase 3: x402 Exact Sandbox Diagnostic Runners
    # ==========================================
    def run_x402_evm_exact_sandbox_diagnostic(self) -> "X402ExactDiagnosticResult":
        from .models import X402ExactDiagnosticResult
        endpoint = "/api/agent/sandbox/x402/evm/exact/basic"
        expected_rejections = ["Invalid TxHash format", "Transaction not found"]

        ok = False
        rejection_reason = None
        diagnostic_class = None
        failure_class = None

        try:
            self.execute_detailed("GET", endpoint, payload={"asset": "USDC"})
        except Exception as e:
            error_msg = str(e)
            if any(r in error_msg for r in expected_rejections):
                ok = True
                rejection_reason = error_msg
                diagnostic_class = "post_settlement_proof_required"
                failure_class = "settlement_model_mismatch"
            else:
                rejection_reason = error_msg

        parsed = getattr(self, "_last_parsed_challenge", None)

        return X402ExactDiagnosticResult(
            ok=ok,
            scenario_id="x402-evm-exact-basic-v1",
            endpoint=endpoint,
            network=parsed.network if parsed else None,
            asset=parsed.asset if parsed else None,
            token_address=parsed.parameters.get("token_address") if parsed else None,
            draft_shape=parsed.draft_shape if parsed else None,
            challenge_shape_ok=parsed is not None,
            expected_rejection=ok,
            rejection_reason=rejection_reason,
            diagnostic_class=diagnostic_class,
            failure_class=failure_class
        )

    async def run_x402_evm_exact_sandbox_diagnostic_async(self) -> "X402ExactDiagnosticResult":
        from .models import X402ExactDiagnosticResult
        endpoint = "/api/agent/sandbox/x402/evm/exact/basic"
        expected_rejections = ["Invalid TxHash format", "Transaction not found"]

        ok = False
        rejection_reason = None
        diagnostic_class = None
        failure_class = None

        try:
            await self.execute_detailed_async("GET", endpoint, payload={"asset": "USDC"})
        except Exception as e:
            error_msg = str(e)
            if any(r in error_msg for r in expected_rejections):
                ok = True
                rejection_reason = error_msg
                diagnostic_class = "post_settlement_proof_required"
                failure_class = "settlement_model_mismatch"
            else:
                rejection_reason = error_msg

        parsed = getattr(self, "_last_parsed_challenge", None)

        return X402ExactDiagnosticResult(
            ok=ok,
            scenario_id="x402-evm-exact-basic-v1",
            endpoint=endpoint,
            network=parsed.network if parsed else None,
            asset=parsed.asset if parsed else None,
            token_address=parsed.parameters.get("token_address") if parsed else None,
            draft_shape=parsed.draft_shape if parsed else None,
            challenge_shape_ok=parsed is not None,
            expected_rejection=ok,
            rejection_reason=rejection_reason,
            diagnostic_class=diagnostic_class,
            failure_class=failure_class
        )

    def run_x402_svm_exact_sandbox_diagnostic(self) -> "X402ExactDiagnosticResult":
        from .models import X402ExactDiagnosticResult
        endpoint = "/api/agent/sandbox/x402/svm/exact/basic"
        expected_rejections = ["Invalid Solana signature format", "Transaction not found"]

        ok = False
        rejection_reason = None
        diagnostic_class = None
        failure_class = None

        try:
            self.execute_detailed("GET", endpoint)
        except Exception as e:
            error_msg = str(e)
            if any(r in error_msg for r in expected_rejections):
                ok = True
                rejection_reason = error_msg
                diagnostic_class = "post_settlement_proof_required"
                failure_class = "settlement_model_mismatch"
            else:
                rejection_reason = error_msg

        parsed = getattr(self, "_last_parsed_challenge", None)

        return X402ExactDiagnosticResult(
            ok=ok,
            scenario_id="x402-svm-exact-basic-v1",
            endpoint=endpoint,
            network=parsed.network if parsed else None,
            asset=parsed.asset if parsed else None,
            token_address=parsed.parameters.get("token_address") if parsed else None,
            draft_shape=parsed.draft_shape if parsed else None,
            challenge_shape_ok=parsed is not None,
            expected_rejection=ok,
            rejection_reason=rejection_reason,
            diagnostic_class=diagnostic_class,
            failure_class=failure_class
        )

    async def run_x402_svm_exact_sandbox_diagnostic_async(self) -> "X402ExactDiagnosticResult":
        from .models import X402ExactDiagnosticResult
        endpoint = "/api/agent/sandbox/x402/svm/exact/basic"
        expected_rejections = ["Invalid Solana signature format", "Transaction not found"]

        ok = False
        rejection_reason = None
        diagnostic_class = None
        failure_class = None

        try:
            await self.execute_detailed_async("GET", endpoint)
        except Exception as e:
            error_msg = str(e)
            if any(r in error_msg for r in expected_rejections):
                ok = True
                rejection_reason = error_msg
                diagnostic_class = "post_settlement_proof_required"
                failure_class = "settlement_model_mismatch"
            else:
                rejection_reason = error_msg

        parsed = getattr(self, "_last_parsed_challenge", None)

        return X402ExactDiagnosticResult(
            ok=ok,
            scenario_id="x402-svm-exact-basic-v1",
            endpoint=endpoint,
            network=parsed.network if parsed else None,
            asset=parsed.asset if parsed else None,
            token_address=parsed.parameters.get("token_address") if parsed else None,
            draft_shape=parsed.draft_shape if parsed else None,
            challenge_shape_ok=parsed is not None,
            expected_rejection=ok,
            rejection_reason=rejection_reason,
            diagnostic_class=diagnostic_class,
            failure_class=failure_class
        )

    # ==========================================
    # Phase 3: External Observation API (M2M)
    # ==========================================
    def _strip_secrets_from_evidence(self, value: Any) -> Any:
        if value is None:
            return {}
        if isinstance(value, dict):
            clean = {}
            for k, v in value.items():
                if _is_secret_key(k):
                    continue
                clean[k] = self._strip_secrets_from_evidence(v) if isinstance(v, (dict, list, tuple)) else v
            return clean
        if isinstance(value, list):
            return [
                self._strip_secrets_from_evidence(v)
                if isinstance(v, (dict, list, tuple)) else v
                for v in value
            ]
        if isinstance(value, tuple):
            return tuple(
                self._strip_secrets_from_evidence(v)
                if isinstance(v, (dict, list, tuple)) else v
                for v in value
            )
        return value

    def submit_external_observation(
        self,
        target_url: str,
        method: str = "GET",
        status_code: int = 402,
        source_scope: str = "external_agent_report",
        evidence_class: str = "self_reported_challenge",
        protocol: Optional[dict] = None,
        evidence: Optional[dict] = None,
        challenge: Optional[dict] = None,
        sdk_version: Optional[str] = None,
        protocol_roles: Optional[list] = None,
        verification_cost_vector: Optional[dict] = None,
    ) -> dict:
        payload = {
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "targetUrl": target_url,
            "method": method,
            "statusCode": status_code,
            "source_scope": source_scope,
            "evidence_class": evidence_class,
            "protocol": self._strip_secrets_from_evidence(protocol or {}),
            "evidence": self._strip_secrets_from_evidence(evidence),
            "challenge": self._strip_secrets_from_evidence(challenge),
            "sdk_version": sdk_version or SDK_VERSION
        }

        if protocol_roles is not None:
            payload["protocol_roles"] = self._strip_secrets_from_evidence(protocol_roles)
        if verification_cost_vector is not None:
            payload["verification_cost_vector"] = self._strip_secrets_from_evidence(verification_cost_vector)

        return self.execute_request("POST", "/api/agent/external/observe", payload=payload)

    async def submit_external_observation_async(
        self,
        target_url: str,
        method: str = "GET",
        status_code: int = 402,
        source_scope: str = "external_agent_report",
        evidence_class: str = "self_reported_challenge",
        protocol: Optional[dict] = None,
        evidence: Optional[dict] = None,
        challenge: Optional[dict] = None,
        sdk_version: Optional[str] = None,
        protocol_roles: Optional[list] = None,
        verification_cost_vector: Optional[dict] = None,
    ) -> dict:
        payload = {
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "targetUrl": target_url,
            "method": method,
            "statusCode": status_code,
            "source_scope": source_scope,
            "evidence_class": evidence_class,
            "protocol": self._strip_secrets_from_evidence(protocol or {}),
            "evidence": self._strip_secrets_from_evidence(evidence),
            "challenge": self._strip_secrets_from_evidence(challenge),
            "sdk_version": sdk_version or SDK_VERSION
        }

        if protocol_roles is not None:
            payload["protocol_roles"] = self._strip_secrets_from_evidence(protocol_roles)
        if verification_cost_vector is not None:
            payload["verification_cost_vector"] = self._strip_secrets_from_evidence(verification_cost_vector)

        return await self.execute_request_async("POST", "/api/agent/external/observe", payload=payload)

    def get_external_observations(
        self, limit: int = 50, rail: Optional[str] = None, quality: Optional[str] = None, source: Optional[str] = None
    ) -> dict:
        params = {"limit": limit}
        if rail: params["rail"] = rail
        if quality: params["quality"] = quality
        if source: params["source"] = source
        return self.execute_request("GET", "/api/agent/external/observations", payload=params)

    async def get_external_observations_async(
        self, limit: int = 50, rail: Optional[str] = None, quality: Optional[str] = None, source: Optional[str] = None
    ) -> dict:
        params = {"limit": limit}
        if rail: params["rail"] = rail
        if quality: params["quality"] = quality
        if source: params["source"] = source
        return await self.execute_request_async("GET", "/api/agent/external/observations", payload=params)

    def submit_unmapped_observation(
        self,
        target_url: str,
        detection_note: str,
        method: str = "GET",
        status_code: int = 402,
        rails_detected: Optional[List[str]] = None,
        source_scope: str = "external_agent_report",
        challenge_shape: Optional[str] = None,
        evidence_class: str = "crawler_detected_402",
        extra_protocol: Optional[dict] = None,
        missing_information: Optional[List[str]] = None,
        sdk_version: Optional[str] = None,
    ) -> dict:
        rail = "unknown"
        if rails_detected and len(rails_detected) == 1 and rails_detected[0] in ["x402", "L402", "MPP"]:
            rail = rails_detected[0]

        protocol = {
            "rail": rail,
            "network": "unknown",
            "asset": "unknown",
            "authorization_scheme": "unknown",
            "draft_shape": challenge_shape or detection_note,
            "payment_intent": "unknown",
            "payment_method": "unknown"
        }
        if extra_protocol:
            protocol.update(self._strip_secrets_from_evidence(extra_protocol))

        evidence = {
            "evidence_class": evidence_class,
            "verification_status": "unverified",
            "verification_method": "none",
            "payment_performed": False,
            "payment_receipt_present": False
        }

        miss_info = missing_information.copy() if missing_information else []
        for m in [detection_note, "settlement_rail_not_declared", "network_not_declared", "asset_not_declared"]:
            if m not in miss_info:
                miss_info.append(m)

        payload = {
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "targetUrl": target_url,
            "method": method.upper(),
            "statusCode": status_code,
            "source_scope": source_scope,
            "protocol": protocol,
            "evidence": evidence,
            "missing_information": miss_info,
            "sdk_version": sdk_version or SDK_VERSION
        }
        return self.execute_request("POST", "/api/agent/external/observe", payload=payload)

    async def submit_unmapped_observation_async(
        self,
        target_url: str,
        detection_note: str,
        method: str = "GET",
        status_code: int = 402,
        rails_detected: Optional[List[str]] = None,
        source_scope: str = "external_agent_report",
        challenge_shape: Optional[str] = None,
        evidence_class: str = "crawler_detected_402",
        extra_protocol: Optional[dict] = None,
        missing_information: Optional[List[str]] = None,
        sdk_version: Optional[str] = None,
    ) -> dict:
        rail = "unknown"
        if rails_detected and len(rails_detected) == 1 and rails_detected[0] in ["x402", "L402", "MPP"]:
            rail = rails_detected[0]

        protocol = {
            "rail": rail,
            "network": "unknown",
            "asset": "unknown",
            "authorization_scheme": "unknown",
            "draft_shape": challenge_shape or detection_note,
            "payment_intent": "unknown",
            "payment_method": "unknown"
        }
        if extra_protocol:
            protocol.update(self._strip_secrets_from_evidence(extra_protocol))

        evidence = {
            "evidence_class": evidence_class,
            "verification_status": "unverified",
            "verification_method": "none",
            "payment_performed": False,
            "payment_receipt_present": False
        }

        miss_info = missing_information.copy() if missing_information else []
        for m in [detection_note, "settlement_rail_not_declared", "network_not_declared", "asset_not_declared"]:
            if m not in miss_info:
                miss_info.append(m)

        payload = {
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "targetUrl": target_url,
            "method": method.upper(),
            "statusCode": status_code,
            "source_scope": source_scope,
            "protocol": protocol,
            "evidence": evidence,
            "missing_information": miss_info,
            "sdk_version": sdk_version or SDK_VERSION
        }
        return await self.execute_request_async("POST", "/api/agent/external/observe", payload=payload)

    def get_surface_preflight(
        self,
        *,
        surface_key: Optional[str] = None,
        target_url: Optional[str] = None,
        method: str = "GET",
        rail: str = "unknown",
        network: str = "unknown",
        asset: str = "unknown",
        authorization_scheme: str = "unknown",
        draft_shape: str = "unknown",
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Fetch public-safe observational memory for a surface before interacting.
        This endpoint is strictly read-only and does NOT execute payments.
        """
        if surface_key and target_url:
            raise ValueError("Provide either surface_key or target_url, not both.")
        if not surface_key and not target_url:
            raise ValueError("Either surface_key or target_url must be provided.")

        if surface_key:
            if surface_key.startswith("surface_"):
                surface_key = surface_key[8:]
            if not re.match(r"^[a-fA-F0-9]{24}$", surface_key):
                raise ValueError("Invalid surface_key format. Must be 24-character hex.")

        if target_url and not target_url.strip():
            raise ValueError("target_url cannot be empty.")

        params = {}
        if surface_key:
            params["surface_key"] = surface_key
        else:
            params.update({
                "target_url": target_url,
                "method": method.upper(),
                "rail": rail,
                "network": network,
                "asset": asset,
                "authorization_scheme": authorization_scheme,
                "draft_shape": draft_shape
            })

        headers = {"User-Agent": CUSTOM_USER_AGENT}
        url = self.base_url.rstrip("/") + "/api/agent/monzen/surface-preflight"

        try:
            # Explicitly NOT using execute_request() to guarantee no payment loops
            res = requests.get(url, params=params, headers=headers, timeout=timeout or 10.0)
            res.raise_for_status()
            data = res.json()
        except Exception as e:
            raise ValueError(f"Failed to fetch surface preflight read model: {e}")

        if data.get("schema_version") != SURFACE_PREFLIGHT_SCHEMA_VERSION:
            raise ValueError(f"Invalid schema_version. Expected {SURFACE_PREFLIGHT_SCHEMA_VERSION}")
        if data.get("not_a_recommendation") is not True:
            raise ValueError("Safety boundary missing: 'not_a_recommendation' must be true")
        if data.get("not_a_verdict") is not True:
            raise ValueError("Safety boundary missing: 'not_a_verdict' must be true")

        guardrails = data.get("guardrails") or {}
        if guardrails.get("final_authority") != "local_runtime":
            raise ValueError("Safety boundary missing: guardrails.final_authority must be local_runtime")
        if guardrails.get("this_read_model_does_not_execute_payments") is not True:
            raise ValueError("Safety boundary missing: read model must not execute payments")
        if guardrails.get("this_read_model_does_not_prove_settlement") is not True:
            raise ValueError("Safety boundary missing: read model must not prove settlement")

        return data

    async def get_surface_preflight_async(
        self,
        *,
        surface_key: Optional[str] = None,
        target_url: Optional[str] = None,
        method: str = "GET",
        rail: str = "unknown",
        network: str = "unknown",
        asset: str = "unknown",
        authorization_scheme: str = "unknown",
        draft_shape: str = "unknown",
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Async: Fetch public-safe observational memory for a surface before interacting.
        This endpoint is strictly read-only and does NOT execute payments.
        """
        if surface_key and target_url:
            raise ValueError("Provide either surface_key or target_url, not both.")
        if not surface_key and not target_url:
            raise ValueError("Either surface_key or target_url must be provided.")

        if surface_key:
            if surface_key.startswith("surface_"):
                surface_key = surface_key[8:]
            if not re.match(r"^[a-fA-F0-9]{24}$", surface_key):
                raise ValueError("Invalid surface_key format. Must be 24-character hex.")

        if target_url and not target_url.strip():
            raise ValueError("target_url cannot be empty.")

        params = {}
        if surface_key:
            params["surface_key"] = surface_key
        else:
            params.update({
                "target_url": target_url,
                "method": method.upper(),
                "rail": rail,
                "network": network,
                "asset": asset,
                "authorization_scheme": authorization_scheme,
                "draft_shape": draft_shape
            })

        headers = {"User-Agent": CUSTOM_USER_AGENT}
        url = self.base_url.rstrip("/") + "/api/agent/monzen/surface-preflight"

        try:
            # Explicitly NOT using execute_request_async() to guarantee no payment loops
            async with httpx.AsyncClient(follow_redirects=True) as client:
                res = await client.get(url, params=params, headers=headers, timeout=timeout or 10.0)
                res.raise_for_status()
                data = res.json()
        except Exception as e:
            raise ValueError(f"Failed to fetch surface preflight read model: {e}")

        if data.get("schema_version") != SURFACE_PREFLIGHT_SCHEMA_VERSION:
            raise ValueError(f"Invalid schema_version. Expected {SURFACE_PREFLIGHT_SCHEMA_VERSION}")
        if data.get("not_a_recommendation") is not True:
            raise ValueError("Safety boundary missing: 'not_a_recommendation' must be true")
        if data.get("not_a_verdict") is not True:
            raise ValueError("Safety boundary missing: 'not_a_verdict' must be true")

        guardrails = data.get("guardrails") or {}
        if guardrails.get("final_authority") != "local_runtime":
            raise ValueError("Safety boundary missing: guardrails.final_authority must be local_runtime")
        if guardrails.get("this_read_model_does_not_execute_payments") is not True:
            raise ValueError("Safety boundary missing: read model must not execute payments")
        if guardrails.get("this_read_model_does_not_prove_settlement") is not True:
            raise ValueError("Safety boundary missing: read model must not prove settlement")

        return data

    def submit_goal_attempt_observation(
        self,
        goal: dict,
        attempt: dict,
        steps: Optional[list] = None,
        outcome: Optional[dict] = None,
        evidence: Optional[dict] = None,
        schema_version: str = "goal_attempt.v1",
        intent_sidecar_metadata: Optional[dict] = None,
        protocol_roles: Optional[list] = None,
        verification_cost_vector: Optional[dict] = None
    ) -> dict:
        """
        Submit a Day 1 Goal Attempt Observation to the LN Church Observatory.

        This records what an agent attempted to accomplish for a declared goal,
        including free, paid, mixed, observe-only, or simulated steps.

        This method is explicit-only:
        - it does not execute payments,
        - it does not recommend recipes,
        - it does not auto-submit telemetry from execute_detailed(),
        - it strips local secrets before submission.

        If outcome is omitted, the attempt is recorded as unassessed.
        """
        payload = {
            "schema_version": schema_version,
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "goal": self._strip_secrets_from_evidence(goal),
            "attempt": self._strip_secrets_from_evidence(attempt),
            "steps": self._strip_secrets_from_evidence(steps or []),
            "evidence": self._strip_secrets_from_evidence(evidence or {})
        }
        if outcome is not None:
            payload["outcome"] = self._strip_secrets_from_evidence(outcome)
        if intent_sidecar_metadata is not None:
            payload["intent_sidecar_metadata"] = self._strip_secrets_from_evidence(intent_sidecar_metadata)
        if protocol_roles is not None:
            payload["protocol_roles"] = self._strip_secrets_from_evidence(protocol_roles)
        if verification_cost_vector is not None:
            payload["verification_cost_vector"] = self._strip_secrets_from_evidence(verification_cost_vector)

        return self.execute_request("POST", "/api/agent/external/attempt/observe", payload=payload)

    async def submit_goal_attempt_observation_async(
        self,
        goal: dict,
        attempt: dict,
        steps: Optional[list] = None,
        outcome: Optional[dict] = None,
        evidence: Optional[dict] = None,
        schema_version: str = "goal_attempt.v1",
        intent_sidecar_metadata: Optional[dict] = None,
        protocol_roles: Optional[list] = None,
        verification_cost_vector: Optional[dict] = None
    ) -> dict:
        """
        Submit a Day 1 Goal Attempt Observation to the LN Church Observatory.

        This records what an agent attempted to accomplish for a declared goal,
        including free, paid, mixed, observe-only, or simulated steps.

        This method is explicit-only:
        - it does not execute payments,
        - it does not recommend recipes,
        - it does not auto-submit telemetry from execute_detailed(),
        - it strips local secrets before submission.

        If outcome is omitted, the attempt is recorded as unassessed.
        """
        payload = {
            "schema_version": schema_version,
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "goal": self._strip_secrets_from_evidence(goal),
            "attempt": self._strip_secrets_from_evidence(attempt),
            "steps": self._strip_secrets_from_evidence(steps or []),
            "evidence": self._strip_secrets_from_evidence(evidence or {})
        }
        if outcome is not None:
            payload["outcome"] = self._strip_secrets_from_evidence(outcome)
        if intent_sidecar_metadata is not None:
            payload["intent_sidecar_metadata"] = self._strip_secrets_from_evidence(intent_sidecar_metadata)
        if protocol_roles is not None:
            payload["protocol_roles"] = self._strip_secrets_from_evidence(protocol_roles)
        if verification_cost_vector is not None:
            payload["verification_cost_vector"] = self._strip_secrets_from_evidence(verification_cost_vector)

        return await self.execute_request_async("POST", "/api/agent/external/attempt/observe", payload=payload)

    def get_goal_attempt_summary(
        self,
        goal_type: Optional[str] = None,
        domain_hint: Optional[str] = None,
        include_unassessed: bool = True,
        limit: int = 20
    ) -> dict:
        """
        Retrieve a lightweight observational summary of goal attempts from the LN Church Observatory.

        This endpoint is strictly free and does not invoke payment logic or 402 negotiation blocks.
        Use this to understand block ratios and upgrade signals prior to querying raw surfaces.
        """
        params = {
            "include_unassessed": "true" if include_unassessed else "false",
            "limit": limit
        }
        if goal_type: params["goal_type"] = goal_type
        if domain_hint: params["domain_hint"] = domain_hint
        if getattr(self, "agent_id", None): params["agentId"] = self.agent_id

        return self.execute_request("GET", "/api/agent/monzen/goal-attempts/summary", payload=params)

    async def get_goal_attempt_summary_async(
        self,
        goal_type: Optional[str] = None,
        domain_hint: Optional[str] = None,
        include_unassessed: bool = True,
        limit: int = 20
    ) -> dict:
        """Async version of get_goal_attempt_summary"""
        params = {
            "include_unassessed": "true" if include_unassessed else "false",
            "limit": limit
        }
        if goal_type: params["goal_type"] = goal_type
        if domain_hint: params["domain_hint"] = domain_hint
        if getattr(self, "agent_id", None): params["agentId"] = self.agent_id

        return await self.execute_request_async("GET", "/api/agent/monzen/goal-attempts/summary", payload=params)

    def get_goal_surface_candidates(
        self,
        goal_type: Optional[str] = None,
        domain_hint: Optional[str] = None,
        prefer_free_first: bool = True,
        include_unassessed: bool = True,
        limit: int = 10,
        asset: AssetType = AssetType.SATS,
        scheme: Optional[str] = "L402"
    ) -> dict:
        """
        Retrieve a paid compact list of observed surfaces used in prior attempts matching the goal type.

        Cost: 1 SAT / 0.001 USDC / 1 JPYC (Bypasses full monzen-graph download overhead).

        Strict Safety Boundaries:
        - This is a historical read model, NOT a recommendation or workflow recipe.
        - Missing outcomes or unassessed steps do not imply execution failure.
        """
        params = {
            "prefer_free_first": "true" if prefer_free_first else "false",
            "include_unassessed": "true" if include_unassessed else "false",
            "limit": limit,
            "asset": asset.value if hasattr(asset, "value") else str(asset),
            "scheme": scheme,
            "agentId": getattr(self, "agent_id", "unknown")
        }
        if goal_type: params["goal_type"] = goal_type
        if domain_hint: params["domain_hint"] = domain_hint

        # GET 402 negotiation loop via execute_detailed internally
        result = self.execute_detailed("GET", "/api/agent/monzen/goal-attempts/candidates", payload=params)
        return result.response

    async def get_goal_surface_candidates_async(
        self,
        goal_type: Optional[str] = None,
        domain_hint: Optional[str] = None,
        prefer_free_first: bool = True,
        include_unassessed: bool = True,
        limit: int = 10,
        asset: AssetType = AssetType.SATS,
        scheme: Optional[str] = "L402"
    ) -> dict:
        """Async version of get_goal_surface_candidates"""
        params = {
            "prefer_free_first": "true" if prefer_free_first else "false",
            "include_unassessed": "true" if include_unassessed else "false",
            "limit": limit,
            "asset": asset.value if hasattr(asset, "value") else str(asset),
            "scheme": scheme,
            "agentId": getattr(self, "agent_id", "unknown")
        }
        if goal_type: params["goal_type"] = goal_type
        if domain_hint: params["domain_hint"] = domain_hint

        result = await self.execute_detailed_async("GET", "/api/agent/monzen/goal-attempts/candidates", payload=params)
        return result.response

    def ensure_reporter_verification(self, public_key_type: str = "evm", force_refresh: bool = False) -> dict:
        """
        Verifies key control with the LN Church to attach a 'key_control_verified' status to your reports.
        Note: This verifies key control, not report truth.
        """
        import time
        from eth_account.messages import encode_defunct
        from eth_account import Account

        if public_key_type != "evm":
            raise ValueError("Only 'evm' public_key_type is currently supported. Solana/Nostr/LN are future scope.")
        if not self.private_key:
            raise ValueError("EVM private_key is strictly required for EVM reporter verification. Custom signers are future scope.")

        now = int(time.time() * 1000)
        cached_until = getattr(self, "_reporter_verified_until", 0)

        if not force_refresh and cached_until > now:
            return {
                "status": "cached",
                "reporter_verification_status": "key_control_verified",
                "verified_until": cached_until,
                "proof_id": getattr(self, "_reporter_proof_id", None)
            }

        # 1. Challenge
        chal_res = self.execute_request("GET", f"/api/agent/identity/challenge?agentId={self.agent_id}&public_key_type=evm")
        challenge_id = chal_res["challenge_id"]
        message = chal_res["message"]

        # 2. Sign
        signable_msg = encode_defunct(text=message)
        signed = Account.from_key(self.private_key).sign_message(signable_msg)
        signature = signed.signature.hex()

        # 3. Verify
        payload = {
            "schema_version": "agent_identity_verify.v1",
            "agentId": self.agent_id,
            "challenge_id": challenge_id,
            "public_key_type": "evm",
            "signature": signature if signature.startswith("0x") else f"0x{signature}"
        }

        verify_res = self.execute_request("POST", "/api/agent/identity/verify", payload=payload)

        self._reporter_verified_until = verify_res["verified_until"]
        self._reporter_proof_id = verify_res["proof_id"]

        return verify_res

    async def ensure_reporter_verification_async(self, public_key_type: str = "evm", force_refresh: bool = False) -> dict:
        """Async version of ensure_reporter_verification. This verifies key control, not report truth."""
        import time
        from eth_account.messages import encode_defunct
        from eth_account import Account

        if public_key_type != "evm":
            raise ValueError("Only 'evm' public_key_type is currently supported. Solana/Nostr/LN are future scope.")
        if not self.private_key:
            raise ValueError("EVM private_key is strictly required for EVM reporter verification. Custom signers are future scope.")


        now = int(time.time() * 1000)
        cached_until = getattr(self, "_reporter_verified_until", 0)

        if not force_refresh and cached_until > now:
            return {
                "status": "cached",
                "reporter_verification_status": "key_control_verified",
                "verified_until": cached_until,
                "proof_id": getattr(self, "_reporter_proof_id", None)
            }

        chal_res = await self.execute_request_async("GET", f"/api/agent/identity/challenge?agentId={self.agent_id}&public_key_type=evm")
        challenge_id = chal_res["challenge_id"]
        message = chal_res["message"]

        signable_msg = encode_defunct(text=message)
        signed = Account.from_key(self.private_key).sign_message(signable_msg)
        signature = signed.signature.hex()

        payload = {
            "schema_version": "agent_identity_verify.v1",
            "agentId": self.agent_id,
            "challenge_id": challenge_id,
            "public_key_type": "evm",
            "signature": signature if signature.startswith("0x") else f"0x{signature}"
        }

        verify_res = await self.execute_request_async("POST", "/api/agent/identity/verify", payload=payload)

        self._reporter_verified_until = verify_res["verified_until"]
        self._reporter_proof_id = verify_res["proof_id"]

        return verify_res

    # ==========================================
    # v1.14.0: Domain Observation Slots & Internal Observatory Worker
    # ==========================================

    def register_domain_observation_slot(
        self,
        domain: str,
        duration_days: int = 7,
        observation_profile: str = "public_safe_light",
        idempotency_key: Optional[str] = None,
        endpoint_path: str = "/api/bazaar/domain-observation-slots",
        **kwargs
    ) -> "DomainObservationSlotResponse":
        """
        Registers a domain for a 7-day public-safe observation run.
        This is an HTTP 402 paid action.

        NOTE: This purchases a slot in the LN Church observatory queue.
        It DOES NOT execute payment to the target domain, and domain_owner_verified is always False in v0.
        """
        from .models import DomainObservationSlotResponse

        if not validate_public_domain_for_observation(domain):
            raise ValueError(f"Invalid public domain provided for observation: {domain}")

        payload = {
            "agentId": getattr(self, "agent_id", "Anonymous_Agent"),
            "domain": domain,
            "duration_days": duration_days,
            "observation_profile": observation_profile
        }
        payload.update(kwargs)

        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        result = self.execute_detailed("POST", endpoint_path, payload=payload, headers=headers)
        data = result.response

        # Backend headers -> body fallback extraction
        rh_lower = {k.lower(): v for k, v in result.response_headers.items()}
        if "result_handle" not in data and "x-ln-result-handle" in rh_lower:
            data["result_handle"] = rh_lower["x-ln-result-handle"]
        if "request_hash" not in data and "x-ln-request-hash" in rh_lower:
            data["request_hash"] = rh_lower["x-ln-request-hash"]

        return DomainObservationSlotResponse(**data)

    def get_domain_observation_request(self, request_id: str) -> "DomainObservationRequestStatus":
        from .models import DomainObservationRequestStatus
        res = self.execute_request("GET", f"/api/agent/external/observatory/domain-observation-requests/{request_id}")
        return DomainObservationRequestStatus(**res)

    def get_domain_observation_read_model(self, domain: str) -> "DomainObservationDomainReadModel":
        from .models import DomainObservationDomainReadModel
        res = self.execute_request("GET", f"/api/agent/external/observatory/domains/{domain}")
        return DomainObservationDomainReadModel(**res)

    # --- Internal Observer (Internal Observatory Worker) Methods ---

    def claim_domain_observation_targets(
        self,
        observer: str = "default_worker",
        limit: int = 5,
        internal_secret: Optional[str] = None
    ) -> "DomainObservationTargetsResponse":
        """
        [Internal Observer API]
        Claims active observation targets for external crawlers (e.g., OpenClaw).
        Requires LN_CHURCH_INTERNAL_SECRET.
        """
        from urllib.parse import urlencode

        import os
        from urllib.parse import urlencode # 💡 追加
        from .models import DomainObservationTargetsResponse

        secret = internal_secret or os.environ.get("LN_CHURCH_INTERNAL_SECRET")
        if not secret:
            raise ValueError("LN_CHURCH_INTERNAL_SECRET is required to claim targets.")

        limit = max(1, min(10, limit))
        headers = {"X-Internal-Secret": secret}

        query = urlencode({"observer": observer, "limit": limit})
        res = self.execute_request("GET", f"/api/agent/external/observation-targets?{query}", headers=headers)
        return DomainObservationTargetsResponse(**res)

    def submit_domain_observation_result(
        self,
        result: Union["DomainObservationResultSubmission", Dict[str, Any]],
        internal_secret: Optional[str] = None
    ) -> "DomainObservationResultResponse":
        """
        [Internal Observer API]
        Submits public-safe observation results back to the LN Church observatory.
        Requires LN_CHURCH_INTERNAL_SECRET.
        """
        import os
        from .models import DomainObservationResultSubmission, DomainObservationResultResponse

        secret = internal_secret or os.environ.get("LN_CHURCH_INTERNAL_SECRET")
        if not secret:
            raise ValueError("LN_CHURCH_INTERNAL_SECRET is required to submit results.")

        if isinstance(result, dict):
            result_obj = DomainObservationResultSubmission(**result)
        else:
            result_obj = result

        # Client-side guardrails
        if not result_obj.no_payment_to_target:
            raise ValueError("Observation result rejected: no_payment_to_target must be True.")

        vcv = result_obj.verification_cost_vector or {}
        if vcv.get("payment_attempts", 0) > 0:
            raise ValueError("Observation result rejected: payment_attempts must be 0.")
        if vcv.get("irreversible_action_attempted") is True:
            raise ValueError("Observation result rejected: irreversible_action_attempted is not allowed.")

        headers = {"X-Internal-Secret": secret}
        res = self.execute_request("POST", "/api/agent/external/domain-observation-results", payload=result_obj.model_dump(), headers=headers)
        return DomainObservationResultResponse(**res)

    def _build_domain_sponsor_proof_headers(
        self,
        result_handle: Optional[str] = None,
        request_hash: Optional[str] = None,
        internal_secret: Optional[str] = None
    ) -> Dict[str, str]:
        import os
        headers = {}
        secret = internal_secret or os.environ.get("LN_CHURCH_INTERNAL_SECRET")

        if secret:
            headers["X-Internal-Secret"] = secret
        else:
            rh = result_handle or os.environ.get("LN_CHURCH_RESULT_HANDLE")
            rhsh = request_hash or os.environ.get("LN_CHURCH_REQUEST_HASH")
            if not rh or not rhsh:
                raise ValueError("Either 'internal_secret', BOTH 'result_handle' and 'request_hash', or a '--proof-file' must be provided.")
            headers["X-LN-Result-Handle"] = rh
            headers["X-LN-Request-Hash"] = rhsh
        return headers

    def create_domain_sponsor_challenge(
        self,
        request_id: str,
        result_handle: Optional[str] = None,
        request_hash: Optional[str] = None,
        internal_secret: Optional[str] = None
    ) -> "DomainSponsorChallengeResponse":
        from .models import DomainSponsorChallengeResponse

        if not _DOMAIN_OBSERVATION_REQUEST_ID_RE.match(request_id):
            raise ValueError(f"Invalid request_id format: {request_id}")

        headers = self._build_domain_sponsor_proof_headers(result_handle, request_hash, internal_secret)

        res = self.execute_request(
            "POST",
            f"/api/agent/external/observatory/domain-observation-requests/{request_id}/sponsor-challenge",
            payload={},
            headers=headers
        )
        return DomainSponsorChallengeResponse(**res)

    def verify_domain_sponsor(
        self,
        request_id: str,
        result_handle: Optional[str] = None,
        request_hash: Optional[str] = None,
        internal_secret: Optional[str] = None
    ) -> "DomainSponsorVerifyResponse":
        from .models import DomainSponsorVerifyResponse

        if not _DOMAIN_OBSERVATION_REQUEST_ID_RE.match(request_id):
            raise ValueError(f"Invalid request_id format: {request_id}")

        headers = self._build_domain_sponsor_proof_headers(result_handle, request_hash, internal_secret)

        res = self.execute_request(
            "POST",
            f"/api/agent/external/observatory/domain-observation-requests/{request_id}/verify-sponsor",
            payload={},
            headers=headers
        )
        return DomainSponsorVerifyResponse(**res)

    def save_domain_sponsor_challenge_document(
        self,
        challenge: "DomainSponsorChallengeResponse",
        file_path: str
    ) -> str:
        import os
        import json
        doc = challenge.challenge_document

        if not doc:
            raise ValueError("challenge.challenge_document is empty.")

        dir_path = os.path.dirname(os.path.abspath(file_path))
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

        return file_path

    def register_verified_domain_track(
        self,
        domain: str,
        *,
        agent_id: Optional[str] = None,
        plan_id: str = "verified_domain_track_lite",
        idempotency_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ) -> "VerifiedDomainTrackRegistrationResponse":
        """
        Register a domain for the Verified Domain Track. (Costs 19 USDC)
        Requires an execution-capable client with a payment policy allowing >= $19 per tx.
        """
        if plan_id != "verified_domain_track_lite":
            raise ValueError(f"Unsupported Verified Domain Track plan: {plan_id}")

        if not validate_public_domain_for_observation(domain):
            raise ValueError(f"Invalid public domain: {domain}")

        payload = {
            "agentId": agent_id or getattr(self, "agent_id", None) or "Anonymous_Agent",
            "domain": domain,
            "plan_id": plan_id,
        }
        payload.update(kwargs)

        from urllib.parse import urlparse
        target_base = base_url if base_url else getattr(self, "base_url", "https://kari.mayim-mayim.com")
        parsed = urlparse(target_base)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        endpoint_path = f"{origin}/api/bazaar/verified-domain-tracks"

        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        result = self.execute_detailed(
            "POST",
            endpoint_path,
            payload=payload,
            headers=headers
        )

        data = result.response.get("data", result.response)

        def get_header(keys: list) -> Optional[str]:
            for k in keys:
                val = result.response_headers.get(k) or result.response_headers.get(k.lower())
                if val: return val
            return None

        result_handle = get_header(["X-LN-Result-Handle", "x-ln-church-result-handle"]) or data.get("result_handle")
        request_hash = get_header(["X-LN-Request-Hash", "x-ln-church-request-hash"]) or data.get("request_hash")

        if "result_handle" not in data and result_handle:
            data["result_handle"] = result_handle
        if "request_hash" not in data and request_hash:
            data["request_hash"] = request_hash

        from .models import VerifiedDomainTrackRegistrationResponse
        return VerifiedDomainTrackRegistrationResponse(**data)

    def get_verified_domain_track_status(self, request_id: str) -> Optional["VerifiedDomainTrackReadModel"]:
        res = self.get_domain_observation_request(request_id)
        return res.verified_domain_track

    def get_domain_verified_track(self, domain: str) -> Optional["VerifiedDomainTrackSummary"]:
        res = self.get_domain_observation_read_model(domain)
        return res.verified_domain_track

    def save_verified_domain_track_proof(
        self,
        registration: "VerifiedDomainTrackRegistrationResponse",
        file_path: str
    ) -> str:
        import os
        import json

        if not registration.result_handle or not registration.request_hash:
            raise ValueError("Missing result_handle or request_hash in registration response.")

        proof_data = {
            "schema_version": "ln_church.verified_domain_track_proof.v1",
            "request_id": registration.request_id,
            "domain": registration.domain,
            "track_plan": registration.track_plan,
            "result_handle": registration.result_handle,
            "request_hash": registration.request_hash,
            "status_url": registration.status_url,
            "sponsor_challenge_url": registration.sponsor_challenge_url,
            "public_read_model_url": registration.public_read_model_url,
            "created_at": registration.created_at
        }

        dir_path = os.path.dirname(os.path.abspath(file_path))
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(proof_data, f, indent=2, ensure_ascii=False)

        try:
            os.chmod(file_path, 0o600)  # Secure the proof file!
        except Exception:
            pass

        return file_path

    # ==========================================
    # v1.8.4: Public API for Evidence & Sandbox
    # ==========================================
    def get_last_sponsored_access_evidence(self):
        return getattr(self, "_last_sponsored_access_evidence", None)

    def get_last_sandbox_evidence(self):
        return getattr(self, "_last_sandbox_evidence", None)

    def extract_sandbox_evidence(self, response_json: dict):
        return build_sandbox_evidence_from_response(response_json)

    def build_sandbox_interop_report_payload(self, **kwargs) -> dict:
        return build_sandbox_interop_report_payload(**kwargs)

    def submit_sandbox_interop_report(self, payload: dict) -> dict:
        res = self.execute_request("POST", "/api/agent/sandbox/interop/report", payload=payload)

        sandbox_ev = self.get_last_sandbox_evidence()
        if sandbox_ev:
            merge_sandbox_report_result(sandbox_ev, res)
        return res

    def get_sandbox_evidence_logs(self, run_id: str) -> dict:
        params = {"run_id": run_id}
        return self.execute_request("GET", "/api/agent/sandbox/interop/logs", payload=params)
