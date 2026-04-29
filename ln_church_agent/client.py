import requests
import httpx
import re
import asyncio
import importlib.metadata
import uuid
import inspect
from urllib.parse import urlparse
from typing import Optional, Dict, Any, Callable, List
import warnings
import base64
import json

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
    _ExecutionUnlock, _FundingPolicy, _EntitlementKind, _ExecutionAccessPlan
)
from .exceptions import (
    PaymentExecutionError, InvoiceParseError, NavigationGuardrailError, 
    CounterpartyTrustError, PaymentChallengeError
)
from .crypto.protocols import EVMSigner, LightningProvider

try:
    from .crypto.protocols import SolanaSigner
except ImportError:
    SolanaSigner = Any

from .challenges import (
    b64url_decode_json, b64url_encode_json, normalize_scheme,
    parse_www_authenticate, parse_legacy_header, parse_challenge_from_response
)

def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("ln-church-agent")
    except importlib.metadata.PackageNotFoundError:
        return "1.6.5" 

SDK_VERSION = get_sdk_version()
CUSTOM_USER_AGENT = f"ln-church-agent/{get_sdk_version()}"

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

def _normalize_scheme(raw_scheme: str) -> str:
    return normalize_scheme(raw_scheme)

class Payment402Client:
    def __init__(
        self, 
        private_key: Optional[str] = None, 
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

        self.solana_signer = solana_signer
        if not self.solana_signer and private_key:
            try:
                from .crypto.solana import LocalSolanaAdapter
                self.solana_signer = LocalSolanaAdapter(private_key)
            except ImportError:
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

    def _parse_challenge(self, response: httpx.Response, expected_asset: str = "USDC", expected_chain_id: Optional[str] = None) -> ParsedChallenge:
        return parse_challenge_from_response(response, expected_asset, expected_chain_id)

    def _parse_www_authenticate(self, auth_header: str, source: ChallengeSource) -> ParsedChallenge:
        return parse_www_authenticate(auth_header, source)

    def _estimate_usd_value(self, parsed: ParsedChallenge) -> float:
        usd_value = 0.0
        if parsed.asset == "USDC": usd_value = parsed.amount
        elif parsed.asset == "JPYC": usd_value = parsed.amount * 0.0067
        elif parsed.asset == "SATS": usd_value = parsed.amount * 0.00065
        return usd_value

    def _sum_budget_events(self, records: List[PaymentEvidenceRecord]) -> float:
        total_usd = 0.0
        seen_receipts = set()
        for record in records:
            if record.session_spend_delta_usd is not None:
                receipt_id = None
                if record.receipt_summary and isinstance(record.receipt_summary, dict):
                    receipt_id = record.receipt_summary.get("receipt_id")
                
                if receipt_id:
                    if receipt_id in seen_receipts:
                        continue
                    seen_receipts.add(receipt_id)
                
                total_usd += record.session_spend_delta_usd
        return total_usd

    def _restore_session_spend_from_evidence(self, context: ExecutionContext) -> None:
        if not self.policy or not self.evidence_repo or context.session_budget_restored:
            return
        try:
            if hasattr(self.evidence_repo, "import_session_evidence"):
                records = self.evidence_repo.import_session_evidence(context)
                restored_usd = self._sum_budget_events(records) if records else 0.0
                self.policy._session_spent_usd = restored_usd
        except Exception:
            pass 
        finally:
            context.session_budget_restored = True

    async def _restore_session_spend_from_evidence_async(self, context: ExecutionContext) -> None:
        if not self.policy or not self.evidence_repo or context.session_budget_restored:
            return
        try:
            if hasattr(self.evidence_repo, "import_session_evidence_async"):
                records = await self.evidence_repo.import_session_evidence_async(context)
            elif hasattr(self.evidence_repo, "import_session_evidence"):
                records = self.evidence_repo.import_session_evidence(context)
            else:
                records = []
            restored_usd = self._sum_budget_events(records) if records else 0.0
            self.policy._session_spent_usd = restored_usd
        except Exception:
            pass
        finally:
            context.session_budget_restored = True

    def _enforce_policy(self, parsed: ParsedChallenge, target_url: str):
        if not self.policy:
            return
        domain = urlparse(target_url).netloc
        if self.policy.blocked_hosts and domain in self.policy.blocked_hosts:
            raise PaymentExecutionError(f"Policy Violation: Host '{domain}' is explicitly blocked.")
        if self.policy.allowed_hosts is not None and domain not in self.policy.allowed_hosts:
            raise PaymentExecutionError(f"Policy Violation: Host '{domain}' is not in allowed_hosts.")
        if parsed.scheme not in self.policy.allowed_schemes:
            raise PaymentExecutionError(f"Policy Violation: Scheme '{parsed.scheme}' is restricted.")
        if parsed.asset not in self.policy.allowed_assets:
            raise PaymentExecutionError(f"Policy Violation: Asset '{parsed.asset}' is restricted.")

        usd_value = self._estimate_usd_value(parsed)
        if usd_value > self.policy.max_spend_per_tx_usd:
            raise PaymentExecutionError(f"Policy Violation: Amount ({usd_value:.4f} USD) exceeds max_spend_per_tx_usd ({self.policy.max_spend_per_tx_usd}).")
        if self.policy._session_spent_usd + usd_value > self.policy.max_spend_per_session_usd:
            raise PaymentExecutionError(f"Policy Violation: Total session spend ({self.policy._session_spent_usd + usd_value:.4f} USD) would exceed limit.")

    def _record_session_spend(self, parsed: ParsedChallenge, l402_report: Optional[Any] = None):
        if not self.policy:
            return
        if l402_report and not l402_report.payment_performed:
            return 
        self.policy._session_spent_usd += self._estimate_usd_value(parsed)

    def _parse_legacy_header(self, header_val: str) -> ParsedChallenge:
        return parse_legacy_header(header_val)

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

    def _process_payment(self, parsed: ParsedChallenge, headers: dict, payload: dict, method: str = "POST", url: str = "") -> tuple[str, str, Optional[Any]]:
        proof_ref = ""
        network_name = parsed.network or "UNKNOWN"
        l402_report = None

        if parsed.scheme in [SchemeType.x402.value, SchemeType.lnc_evm_relay.value, SchemeType.lnc_evm_transfer.value, "exact"]:
            if not self.evm_signer:
                raise PaymentExecutionError(f"{parsed.scheme} 決済には evm_signer が必要です。")
            
            dest = parsed.parameters.get("destination") or parsed.parameters.get("payTo")
            if not dest:
                raise PaymentExecutionError("HATEOAS Error: Treasury address is missing.")

            chain_id_to_use = 137
            if parsed.parameters.get("chain_id"):
                chain_id_to_use = int(parsed.parameters.get("chain_id"))
            elif parsed.network.startswith("eip155:"):
                chain_id_to_use = int(parsed.network.split(":")[1])

            if parsed.scheme == "exact":
                eip3009_payload = self.evm_signer.generate_eip3009_payload(
                    parsed.asset, parsed.amount, dest, chain_id_to_use, 
                    parsed.parameters.get("token_address")
                )
                proof_ref = "eip3009_signature_payload"
                
            elif parsed.scheme == SchemeType.lnc_evm_transfer.value:
                proof_ref = self.evm_signer.execute_lnc_evm_transfer_settlement(
                    parsed.asset, parsed.amount, dest, chain_id_to_use, 
                    parsed.parameters.get("token_address"), self.evm_rpc_url
                )
                
            elif parsed.scheme == SchemeType.lnc_evm_relay.value:
                proof_ref = self.evm_signer.execute_lnc_evm_relay_settlement(
                    parsed.asset, parsed.amount, parsed.parameters.get("relayer_endpoint"), 
                    dest, chain_id_to_use, parsed.parameters.get("token_address")
                )
                
            elif parsed.scheme == SchemeType.x402.value:
                from .crypto.evm import sign_standard_x402_evm
                proof_ref = sign_standard_x402_evm(self.private_key, parsed)

            if parsed.scheme == "exact":
                raw_accepted = parsed.parameters.get("_raw_accepted")
                if not raw_accepted:
                    decimals = 6 if parsed.asset == "USDC" else 18
                    raw_amount_str = str(int(parsed.amount * (10 ** decimals)))
                    raw_asset_for_payload = parsed.parameters.get("token_address") if parsed.parameters.get("token_address") else parsed.asset
                    raw_accepted = {
                        "scheme": "exact", "network": parsed.network, "asset": raw_asset_for_payload,
                        "amount": raw_amount_str, "payTo": dest, "maxTimeoutSeconds": 3600,
                        "extra": {"name": "USD Coin", "version": "2"}
                    }
                
                raw_resource = parsed.parameters.get("_raw_resource")
                if not raw_resource:
                    raw_resource = {"url": url, "description": "Agent Payment", "mimeType": "application/json"}
                
                cdp_v2_payload = {
                    "x402Version": 2,
                    "accepted": raw_accepted,
                    "payload": eip3009_payload,
                    "resource": raw_resource
                }
                
                raw_extensions = parsed.parameters.get("_raw_extensions")
                if raw_extensions:
                    cdp_v2_payload["extensions"] = raw_extensions
                
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
                raise PaymentExecutionError("solana_signer が必要です。")
            dest = parsed.parameters.get("payTo") or parsed.parameters.get("destination")
            proof_ref = self.solana_signer.execute_lnc_solana_transfer_settlement(
                parsed.asset, parsed.amount, dest, parsed.parameters.get("reference")
            )
            agent_id = getattr(self, "agent_id", "Anonymous")
            payload["paymentAuth"] = {"scheme": parsed.scheme, "proof": proof_ref, "agentId": agent_id}
            headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        elif parsed.scheme in [SchemeType.l402.value, SchemeType.mpp.value, "Payment"]:
            if getattr(parsed, "payment_intent", None) == "session":
                raise PaymentExecutionError("mpp_session_not_supported_yet")

            if parsed.scheme == "Payment" and getattr(parsed, "draft_shape", None) == "payment-auth-draft":
                if not getattr(self, "allow_legacy_payment_auth_fallback", False):
                    raise PaymentExecutionError("unsupported-payment-auth-json")
            
            if parsed.scheme == SchemeType.l402.value:
                host = urlparse(url).netloc
                is_get = method.upper() == "GET"
                is_empty_payload = not bool(payload)
                
                use_delegate = (
                    self.prefer_lightninglabs_l402 and 
                    host in self.l402_delegate_allowed_hosts and 
                    is_get and 
                    is_empty_payload
                )

                if use_delegate and self.l402_executor:
                    l402_report = self.l402_executor.execute_l402(url, method, parsed, headers, payload)
                else:
                    from .adapters.l402_delegate import NativeL402Executor
                    if not self.ln_adapter:
                        raise PaymentExecutionError(f"L402決済には ln_adapter が必要です。")
                    native_exec = NativeL402Executor(self.ln_adapter)
                    l402_report = native_exec.execute_l402(url, method, parsed, headers, payload)

                headers["Authorization"] = l402_report.authorization_value
                proof_ref = l402_report.preimage or ""
                network_name = "Lightning"

            else:
                if not self.ln_adapter:
                    raise PaymentExecutionError(f"{parsed.scheme} 決済には ln_adapter が必要です。")
                invoice = parsed.parameters.get("invoice")
                if not invoice:
                    raise InvoiceParseError("Challenge にインボイスが含まれていません。")

                proof_ref = self.ln_adapter.pay_invoice(invoice)
                
                charge_id = parsed.parameters.get("charge")
                if charge_id:
                    headers["Authorization"] = f"{parsed.scheme} {charge_id}:{proof_ref}"
                else:
                    headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        return proof_ref, network_name, l402_report

    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        result = self.execute_detailed(method, endpoint_path, payload, headers)
        return result.response

    def _resolve_next_action(self, error_data: dict, headers: dict) -> tuple[Optional[NextAction], str]:
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

    def execute_detailed(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, 
        _current_hop: int = 0, _payment_retry_count: int = 0,
        context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None
    ) -> ExecutionResult:
        
        context = context or ExecutionContext()
        self._restore_session_spend_from_evidence(context)
        
        url = endpoint_path if endpoint_path.startswith("http") else f"{self.base_url}{endpoint_path}"
        headers = dict(headers or {}) 
        if not any(k.lower() == "user-agent" for k in headers.keys()):
            headers["User-Agent"] = CUSTOM_USER_AGENT
        
        payload = payload or {}
        method_upper = method.upper()

        req_kwargs = {
            "json": None if method_upper == "GET" else payload,
            "params": payload if method_upper == "GET" else None,
            "headers": headers
        }

        res = requests.request(method_upper, url, **req_kwargs)

        if 200 <= res.status_code < 300:
            try:
                raw_json = res.json() if res.content else {"status": "success"}
                resp_data = raw_json if isinstance(raw_json, dict) else {"status": "success", "data": raw_json}
            except Exception:
                resp_data = {"status": "success", "message": "unparseable"}

            result = ExecutionResult(response=resp_data, final_url=url, retry_count=_payment_retry_count)
            
            raw_response = res.headers.get("PAYMENT-RESPONSE")
            token = None
            if raw_response and isinstance(raw_response, str):
                if not raw_response.startswith('status='):
                    payload_b64 = _b64url_decode(raw_response)
                    token = payload_b64.get("receipt") if payload_b64 else raw_response
                else:
                    match = re.search(r'receipt="?([^",]+)"?', raw_response)
                    token = match.group(1) if match else raw_response
            else:
                candidate = res.headers.get("Payment-Receipt")
                token = candidate if isinstance(candidate, str) else None

            if token and _current_receipt:
                _current_receipt.receipt_token = str(token)
                _current_receipt.source = AttestationSource.SERVER_JWS
                _current_receipt.verification_status = "verified"
            
            if outcome_matcher:
                context.hints["target_url"] = url
                context.hints["http_method"] = method

                sig = inspect.signature(outcome_matcher)
                if len(sig.parameters) == 3:
                    result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                else:
                    result.outcome = outcome_matcher(resp_data, context)
            return result

        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries:
                raise PaymentExecutionError("Max 402 retries exceeded")
            
            parsed = self._parse_challenge(
                res, 
                expected_asset=payload.get("asset", "SATS"),
                expected_chain_id=str(payload.get("chainId")) if payload.get("chainId") else None
            )
            self._last_parsed_challenge = parsed
            self._enforce_policy(parsed, url)

            if self.evidence_repo:
                past_records = self.evidence_repo.import_evidence(url, context)
                if past_records:
                    context.past_evidence = past_records

            evidence = TrustEvidence(
                url=url,
                challenge=parsed,
                host_metadata={},
                agent_hints=context.hints
            )

            decision = None
            payment_completed = False
            delta_usd = None
            receipt = None
            
            try:
                for evaluator in self.trust_evaluators:
                    sig = inspect.signature(evaluator)
                    if len(sig.parameters) == 2:
                        decision = evaluator(evidence, context)
                    else:
                        decision = evaluator(url, parsed, context)
                    
                    if not decision.is_trusted:
                        raise CounterpartyTrustError(f"Trust Evaluation Blocked Payment: {decision.reason}")

                proof_ref, network_name, l402_report = self._process_payment(parsed, headers, payload, method=method, url=url)
                self._record_session_spend(parsed, l402_report)
                
                payment_completed = True
                delta_usd = self._estimate_usd_value(parsed)

                receipt = SettlementReceipt(
                    receipt_id=str(uuid.uuid4()),
                    scheme=parsed.scheme, network=network_name, asset=parsed.asset,
                    settled_amount=parsed.amount, proof_reference=proof_ref,
                    verification_status="verified" if network_name == "Lightning" else "self_reported",
                    delegate_source=l402_report.delegate_source if l402_report else "native",
                    payment_hash=l402_report.payment_hash if l402_report else None,
                    fee_sats=l402_report.fee_sats if l402_report else None,
                    cached_token_used=l402_report.cached_token_used if l402_report else False,
                    payment_performed=l402_report.payment_performed if l402_report else True,
                    endpoint=url
                )
                self.last_receipt = receipt

                next_result = self.execute_detailed(
                    method, url, payload, headers, _current_hop, _payment_retry_count + 1,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=receipt
                )
                
                next_result.settlement_receipt = receipt
                next_result.used_scheme = parsed.scheme
                next_result.used_asset = parsed.asset
                next_result.verification_status = receipt.verification_status
                
                if self.evidence_repo:
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                        trust_decision=decision,
                        receipt_summary={"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status},
                        outcome=next_result.outcome,
                        session_spend_delta_usd=delta_usd, 
                        delegate_source=l402_report.delegate_source if l402_report else "native",
                        payment_hash=l402_report.payment_hash if l402_report else None,
                        fee_sats=l402_report.fee_sats if l402_report else None,
                        cached_token_used=l402_report.cached_token_used if l402_report else False,
                        payment_performed=l402_report.payment_performed if l402_report else True
                    )

                    self.evidence_repo.export_evidence(record, context)

                return next_result

            except Exception as e:
                if self.evidence_repo:
                    record_kwargs = {
                        "session_id": context.session_id, "correlation_id": context.correlation_id,
                        "target_url": url, "method": method, "scheme": parsed.scheme, "asset": parsed.asset, "amount": parsed.amount,
                        "trust_decision": decision, "error_message": str(e)
                    }
                    if payment_completed:
                        record_kwargs["session_spend_delta_usd"] = delta_usd
                        record_kwargs["receipt_summary"] = {"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status}
                        
                    record = PaymentEvidenceRecord(**record_kwargs)
                    self.evidence_repo.export_evidence(record, context)
                raise

        try:
            error_data = res.json()
        except Exception:
            error_data = {}

        next_action, source = self._resolve_next_action(error_data, res.headers)

        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            
            is_unsafe = next_method not in ["GET", "HEAD"]
            if next_url:
                current_netloc = urlparse(url).netloc
                next_netloc = urlparse(next_url).netloc if next_url.startswith("http") else current_netloc
                if next_netloc and current_netloc != next_netloc:
                    allowed_hosts = context.hints.get("allowed_hosts", [])
                    if next_netloc not in allowed_hosts:
                        is_unsafe = True

            if is_unsafe and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")

            if next_url and next_method != "NONE":
                forbidden_headers = {"authorization", "cookie", "proxy-authorization", "host", "content-length"}
                safe_suggested = {k: v for k, v in (next_action.suggested_headers or {}).items() if k.lower() not in forbidden_headers}

                merged_headers = {**headers, **safe_suggested}
                
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                next_result = self.execute_detailed(
                    next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=_current_receipt
                )
                
                if self.evidence_repo:
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, navigation_source=source,
                        outcome=next_result.outcome
                    )
                    self.evidence_repo.export_evidence(record, context)
                return next_result

        error_msg = error_data.get('message', res.text)
        raise PaymentExecutionError(f"API Error {res.status_code}: {error_msg}")

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
        
        context = context or ExecutionContext()
        await self._restore_session_spend_from_evidence_async(context)
        
        url = endpoint_path if endpoint_path.startswith("http") else f"{self.base_url}{endpoint_path}"
        headers = dict(headers or {}) 
        if not any(k.lower() == "user-agent" for k in headers.keys()):
            headers["User-Agent"] = CUSTOM_USER_AGENT

        payload = payload or {}
        method_upper = method.upper()
        req_kwargs = {
            "json": None if method_upper == "GET" else payload,
            "params": payload if method_upper == "GET" else None,
            "headers": headers
        }

        if self._async_client is None:
            self._async_client = httpx.AsyncClient(follow_redirects=True)

        res = await self._async_client.request(method_upper, url, **req_kwargs)

        if 200 <= res.status_code < 300:
            try:
                raw_json = res.json() if res.content else {"status": "success"}
                resp_data = raw_json if isinstance(raw_json, dict) else {"status": "success", "data": raw_json}
            except Exception:
                resp_data = {"status": "success", "message": "unparseable"}

            result = ExecutionResult(response=resp_data, final_url=url, retry_count=_payment_retry_count)
            
            raw_response = res.headers.get("PAYMENT-RESPONSE")
            token = None
            if raw_response and isinstance(raw_response, str):
                if not raw_response.startswith('status='):
                    payload_b64 = _b64url_decode(raw_response)
                    token = payload_b64.get("receipt") if payload_b64 else raw_response
                else:
                    match = re.search(r'receipt="?([^",]+)"?', raw_response)
                    token = match.group(1) if match else raw_response
            else:
                candidate = res.headers.get("Payment-Receipt")
                token = candidate if isinstance(candidate, str) else None

            if token and _current_receipt:
                _current_receipt.receipt_token = str(token)
                _current_receipt.source = AttestationSource.SERVER_JWS
                _current_receipt.verification_status = "verified"
            
            if outcome_matcher:
                context.hints["target_url"] = url
                context.hints["http_method"] = method

                loop = asyncio.get_running_loop()
                sig = inspect.signature(outcome_matcher)
                if len(sig.parameters) == 3:
                    result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                else:
                    result.outcome = outcome_matcher(resp_data, context)
            return result

        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries: 
                raise PaymentExecutionError("Max 402 retries exceeded")
            
            parsed = self._parse_challenge(
                res, 
                expected_asset=payload.get("asset", "SATS"),
                expected_chain_id=str(payload.get("chainId")) if payload.get("chainId") else None
            )
            self._last_parsed_challenge = parsed
            self._enforce_policy(parsed, url)

            if getattr(self, "evidence_repo", None):
                if hasattr(self.evidence_repo, "import_evidence_async"):
                    past_records = await self.evidence_repo.import_evidence_async(url, context)
                else:
                    past_records = self.evidence_repo.import_evidence(url, context)
                
                if past_records:
                    context.past_evidence = past_records

            evidence = TrustEvidence(
                url=url,
                challenge=parsed,
                host_metadata={},
                agent_hints=context.hints
            )

            decision = None
            payment_completed = False
            delta_usd = None
            receipt = None
            
            try:
                loop = asyncio.get_running_loop()
                for evaluator in self.trust_evaluators:
                    sig = inspect.signature(evaluator)
                    if len(sig.parameters) == 2:
                        decision = await loop.run_in_executor(None, evaluator, evidence, context)
                    else:
                        decision = await loop.run_in_executor(None, evaluator, url, parsed, context)
                    
                    if not decision.is_trusted:
                        raise CounterpartyTrustError(f"Trust Evaluation Blocked Payment: {decision.reason}")

                def _process_wrapper():
                    return self._process_payment(parsed, headers, payload, method=method, url=url)
                
                proof_ref, network_name, l402_report = await loop.run_in_executor(None, _process_wrapper)
                self._record_session_spend(parsed, l402_report)
                
                payment_completed = True
                delta_usd = self._estimate_usd_value(parsed)

                receipt = SettlementReceipt(
                    receipt_id=str(uuid.uuid4()),
                    scheme=parsed.scheme, network=network_name, asset=parsed.asset,
                    settled_amount=parsed.amount, proof_reference=proof_ref,
                    verification_status="verified" if network_name == "Lightning" else "self_reported",
                    delegate_source=l402_report.delegate_source if l402_report else "native",
                    payment_hash=l402_report.payment_hash if l402_report else None,
                    fee_sats=l402_report.fee_sats if l402_report else None,
                    cached_token_used=l402_report.cached_token_used if l402_report else False,
                    payment_performed=l402_report.payment_performed if l402_report else True,
                    endpoint=url
                )
                self.last_receipt = receipt

                next_result = await self.execute_detailed_async(
                    method, url, payload, headers, _current_hop, _payment_retry_count + 1,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=receipt
                )
                
                next_result.settlement_receipt = receipt
                next_result.used_scheme = parsed.scheme
                next_result.used_asset = parsed.asset
                next_result.verification_status = receipt.verification_status

                if getattr(self, "evidence_repo", None):
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                        trust_decision=decision,
                        receipt_summary={"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status},
                        outcome=next_result.outcome,
                        session_spend_delta_usd=delta_usd,
                        delegate_source=l402_report.delegate_source if l402_report else "native",
                        payment_hash=l402_report.payment_hash if l402_report else None,
                        fee_sats=l402_report.fee_sats if l402_report else None,
                        cached_token_used=l402_report.cached_token_used if l402_report else False,
                        payment_performed=l402_report.payment_performed if l402_report else True
                    )
                    if hasattr(self.evidence_repo, "export_evidence_async"):
                        await self.evidence_repo.export_evidence_async(record, context)
                    else:
                        self.evidence_repo.export_evidence(record, context)

                return next_result

            except Exception as e:
                if getattr(self, "evidence_repo", None):
                    record_kwargs = {
                        "session_id": context.session_id, "correlation_id": context.correlation_id,
                        "target_url": url, "method": method, "scheme": parsed.scheme, "asset": parsed.asset, "amount": parsed.amount,
                        "trust_decision": decision, "error_message": str(e)
                    }
                    if payment_completed:
                        record_kwargs["session_spend_delta_usd"] = delta_usd
                        record_kwargs["receipt_summary"] = {"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status}
                        
                    record = PaymentEvidenceRecord(**record_kwargs)
                    
                    if hasattr(self.evidence_repo, "export_evidence_async"):
                        await self.evidence_repo.export_evidence_async(record, context)
                    else:
                        self.evidence_repo.export_evidence(record, context)
                raise
        
        try:
            error_data = res.json()
        except Exception:
            error_data = {}

        next_action, source = self._resolve_next_action(error_data, res.headers)

        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            
            is_unsafe = next_method not in ["GET", "HEAD"]
            if next_url:
                current_netloc = urlparse(url).netloc
                next_netloc = urlparse(next_url).netloc if next_url.startswith("http") else current_netloc
                if next_netloc and current_netloc != next_netloc:
                    allowed_hosts = context.hints.get("allowed_hosts", [])
                    if next_netloc not in allowed_hosts:
                        is_unsafe = True

            if is_unsafe and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")

            if next_url and next_method != "NONE":
                forbidden_headers = {"authorization", "cookie", "proxy-authorization", "host", "content-length"}
                safe_suggested = {k: v for k, v in (next_action.suggested_headers or {}).items() if k.lower() not in forbidden_headers}

                merged_headers = {**headers, **safe_suggested}
                
                merged_payload = {**payload, **(next_action.suggested_payload or {})} 
                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                next_result = await self.execute_detailed_async(
                    next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=_current_receipt
                )
                
                if getattr(self, "evidence_repo", None):
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, navigation_source=source,
                        outcome=next_result.outcome
                    )
                    if hasattr(self.evidence_repo, "export_evidence_async"):
                        await self.evidence_repo.export_evidence_async(record, context)
                    else:
                        self.evidence_repo.export_evidence(record, context)
                return next_result

        error_msg = error_data.get('message', res.text)
        raise PaymentExecutionError(f"API Error {res.status_code}: {error_msg}")

    async def aclose(self):
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    async def __aenter__(self):
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(follow_redirects=True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

class LnChurchClient(Payment402Client):
    def __init__(
        self, 
        agent_id: Optional[str] = None, 
        private_key: Optional[str] = None, 
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

    def has_valid_scoped_grant(self, target_path: str, method: str) -> bool:
        if not self.grant_token: return False
        claims = _decode_jwt_payload(self.grant_token)
        if not claims: return False

        import time
        if claims.get("exp", 0) < time.time(): return False
        if claims.get("sub") != self.agent_id: return False
        aud = claims.get("aud", "")
        if aud.rstrip("/") != self.base_url.rstrip("/"): return False

        scope = claims.get("scope", {})
        routes = scope.get("routes", [])
        methods = scope.get("methods", [])

        if target_path not in routes: return False
        if method.upper() not in [m.upper() for m in methods]: return False

        return True

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

        # L402側もサーバーレシートの存在を厳密に判定
        payment_receipt_present = bool(
            receipt
            and getattr(receipt, "receipt_token", None)
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

        # L402側もサーバーレシートの存在を厳密に判定
        payment_receipt_present = bool(
            receipt
            and getattr(receipt, "receipt_token", None)
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
            and getattr(receipt, "receipt_token", None)
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
            and getattr(receipt, "receipt_token", None)
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
            urlparse(target_url).netloc in self.l402_delegate_allowed_hosts
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
            urlparse(target_url).netloc in self.l402_delegate_allowed_hosts
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