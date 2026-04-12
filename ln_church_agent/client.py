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

from eth_account import Account
from .models import (
    AssetType, SchemeType, OmikujiResponse, AgentIdentity, ConfessionResponse, 
    HonoResponse, CompareResponse, AggregateResponse, BenchmarkOverviewResponse,
    HateoasErrorResponse, MonzenTraceResponse, MonzenMetricsResponse,
    MonzenGraphResponse, PaymentPolicy, SettlementReceipt,
    ParsedChallenge, ExecutionResult, 
    ExecutionContext, TrustDecision, OutcomeSummary, TrustEvidence,
    PaymentEvidenceRecord, EvidenceRepository 
)
from .exceptions import PaymentExecutionError, InvoiceParseError, NavigationGuardrailError, CounterpartyTrustError
from .crypto.protocols import EVMSigner, LightningProvider

try:
    from .crypto.protocols import SolanaSigner
except ImportError:
    SolanaSigner = Any

def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("ln-church-agent")
    except importlib.metadata.PackageNotFoundError:
        return "1.5.2" 

SDK_VERSION = get_sdk_version()
CUSTOM_USER_AGENT = f"ln-church-agent/{get_sdk_version()}"

# 内部用のレガシーSchemeマッピングヘルパー
# ⛩️ 本殿の新しい命名規則（語彙体系）へ追随
def _normalize_scheme(raw_scheme: str) -> str:
    s = raw_scheme.lower()
    # 独自仕様のレガシーエイリアスを正規化
    if s == "x402-direct": return SchemeType.lnc_evm_transfer.value
    if s == "x402-solana": return SchemeType.lnc_solana_transfer.value
    if s == "x402-relay":  return SchemeType.lnc_evm_relay.value
    
    # bare 'x402' は標準仕様としてそのまま通す
    return raw_scheme

# ==========================================
# 🌟 CORE: 汎用的な402決済 & HATEOASクライアント
# ==========================================
class Payment402Client:
    # ... (init, parse_challenge, enforce_policy 等の内部実装は変更なし) ...
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

    # ==========================================
    # v1.3.0: 共通責務の分離 (Cold Spec & Policy Layer)
    # ==========================================
    def _parse_challenge(self, response: requests.Response, default_asset: str) -> ParsedChallenge:
        """HTTP 402レスポンスからChallengeをパースし、正規化モデルを生成する"""
        data = response.json()
        challenge = data.get("challenge", {})
        instruction = data.get("instruction_for_agents", {})
        auth_header = response.headers.get("WWW-Authenticate", "")
        # ★ 改修: x-402-payment-required ヘッダーから network (CAIP-2) などの情報を抽出
        x402_header = response.headers.get("x-402-payment-required", "")

        def safe_extract(pattern, text, fallback):
            match = re.search(pattern, text)
            return match.group(1) if match else fallback

        raw_scheme = challenge.get("scheme", "UNKNOWN")
        normalized_scheme = _normalize_scheme(raw_scheme)
        
        # CAIP-2 ネットワークの抽出 (ヘッダー優先、ペイロードフォールバック)
        network_id = safe_extract(r'network="?([^";]+)"?', x402_header, None) or challenge.get("network")

        return ParsedChallenge(
            scheme=normalized_scheme,
            network=network_id, # ★ 追加
            amount=float(challenge.get("amount", 0)),
            asset=challenge.get("asset", default_asset),
            invoice=challenge.get("parameters", {}).get("invoice") or safe_extract(r'invoice="([^"]+)"', auth_header, None),
            macaroon=safe_extract(r'macaroon="([^"]+)"', auth_header, None),
            charge_id=challenge.get("parameters", {}).get("charge") or safe_extract(r'charge="([^"]+)"', auth_header, None),
            destination=challenge.get("parameters", {}).get("destination") or instruction.get("treasury_address") or challenge.get("parameters", {}).get("payTo"),
            chain_id=str(challenge.get("parameters", {}).get("chain_id") or instruction.get("chain_id") or ""), # ★ strにキャスト
            token_address=challenge.get("parameters", {}).get("token_address") or instruction.get("token_address"),
            relayer_endpoint=instruction.get("relayer_endpoint"),
            reference=challenge.get("parameters", {}).get("reference") or instruction.get("reference"),
            raw_headers=dict(response.headers)
        )

    def _enforce_policy(self, parsed: ParsedChallenge, target_url: str):
        """正規化されたChallengeに対してセキュリティポリシーを強制する"""
        if not self.policy:
            return

        domain = urlparse(target_url).netloc

        if self.policy.blocked_hosts and domain in self.policy.blocked_hosts:
            raise PaymentExecutionError(f"Policy Violation: Host '{domain}' is explicitly blocked.")
        if self.policy.allowed_hosts is not None and domain not in self.policy.allowed_hosts:
            raise PaymentExecutionError(f"Policy Violation: Host '{domain}' is not in allowed_hosts.")

        # Scheme validation (Canonical mapping)
        if parsed.scheme not in self.policy.allowed_schemes and raw_scheme not in self.policy.allowed_schemes:
            raise PaymentExecutionError(f"Policy Violation: Scheme '{parsed.scheme}' is restricted.")
            
        if parsed.asset not in self.policy.allowed_assets:
            raise PaymentExecutionError(f"Policy Violation: Asset '{parsed.asset}' is restricted.")

        usd_value = 0.0
        if parsed.asset == "USDC": usd_value = parsed.amount
        elif parsed.asset == "JPYC": usd_value = parsed.amount * 0.0067
        elif parsed.asset == "SATS": usd_value = parsed.amount * 0.00065

        if usd_value > self.policy.max_spend_per_tx_usd:
            raise PaymentExecutionError(
                f"Policy Violation: Amount ({usd_value:.4f} USD) exceeds max_spend_per_tx_usd ({self.policy.max_spend_per_tx_usd})."
            )

        # セッション累計額のチェック（今回のリクエスト分を加算して上限を超えるか判定）
        if self.policy._session_spent_usd + usd_value > self.policy.max_spend_per_session_usd:
            raise PaymentExecutionError(
                f"Policy Violation: Total session spend ({self.policy._session_spent_usd + usd_value:.4f} USD) "
                f"would exceed limit ({self.policy.max_spend_per_session_usd} USD)."
            )


    def _record_session_spend(self, parsed: ParsedChallenge):
        """決済成功後にのみセッション予算を消費する"""
        if not self.policy:
            return
        usd_value = 0.0
        if parsed.asset == "USDC": usd_value = parsed.amount
        elif parsed.asset == "JPYC": usd_value = parsed.amount * 0.0067
        elif parsed.asset == "SATS": usd_value = parsed.amount * 0.00065
        self.policy._session_spent_usd += usd_value

    def execute_paid_action(self, *args, **kwargs) -> dict:
        """
        [Deprecated] 1.2.x互換シグネチャと1.3.x新シグネチャを両方サポートする互換ラッパー。
        """
        warnings.warn(
            "execute_paid_action() is deprecated. Use execute_request() or execute_detailed() instead.",
            DeprecationWarning,
            stacklevel=2
        )

        # 1.2.x 互換判定: execute_paid_action(endpoint_path, payload, headers=None)
        # 第一引数がパス(str)かつ、第二引数がペイロード(dict)の場合は旧形式とみなす
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            endpoint_path = args[0]
            payload = args[1]
            headers = args[2] if len(args) > 2 else kwargs.get("headers")
            return self.execute_request("POST", endpoint_path, payload, headers)

        # 1.3.x 新形式: execute_paid_action(method, endpoint_path, payload=None, headers=None)
        method = args[0] if len(args) > 0 else kwargs.get("method", "POST")
        endpoint_path = args[1] if len(args) > 1 else kwargs.get("endpoint_path")
        payload = args[2] if len(args) > 2 else kwargs.get("payload")
        headers = args[3] if len(args) > 3 else kwargs.get("headers")
        
        return self.execute_request(method, endpoint_path, payload, headers)


    def _process_payment(self, parsed: ParsedChallenge, headers: dict, payload: dict) -> tuple[str, str]:
        """実際の決済実行をカプセル化 (同期・非同期共通で利用)"""
        proof_ref = ""
        network_name = parsed.network or "UNKNOWN" # CAIP-2を優先

        # ★ 改修: Canonical Scheme と CAIP-2 ネットワーク指定に基づく決済ルーティング
        if parsed.scheme in [SchemeType.x402.value, SchemeType.lnc_evm_relay.value, SchemeType.lnc_evm_transfer.value]:
            if not self.evm_signer:
                raise PaymentExecutionError(f"{parsed.scheme} 決済には evm_signer が必要です。")
            if not parsed.destination:
                raise PaymentExecutionError("HATEOAS Error: Treasury address is missing.")

            # CAIP-2 の eip155:137 等から chain_id を推測（指定があれば）
            chain_id_to_use = 137 # default fallback
            if parsed.chain_id and parsed.chain_id.isdigit():
                chain_id_to_use = int(parsed.chain_id)
            elif parsed.network and parsed.network.startswith("eip155:"):
                try:
                    chain_id_to_use = int(parsed.network.split(":")[1])
                except ValueError:
                    pass

            if parsed.scheme in [SchemeType.x402.value, SchemeType.lnc_evm_relay.value]:
                if not parsed.relayer_endpoint:
                    raise PaymentExecutionError("HATEOAS Error: Relayer endpoint is missing.")
                proof_ref = self.evm_signer.execute_x402_gasless(
                    parsed.asset, parsed.amount, parsed.relayer_endpoint, 
                    parsed.destination, chain_id_to_use, parsed.token_address
                )
                network_name = network_name if network_name != "UNKNOWN" else f"EVM-Relay({chain_id_to_use})"
            
            elif parsed.scheme == SchemeType.lnc_evm_transfer.value:
                if not self.evm_rpc_url:
                    raise PaymentExecutionError("RPC URL is required for lnc-evm-transfer payment.")
                proof_ref = self.evm_signer.execute_x402_direct(
                    parsed.asset, parsed.amount, parsed.destination, 
                    chain_id_to_use, parsed.token_address, self.evm_rpc_url
                )
                network_name = network_name if network_name != "UNKNOWN" else f"EVM-Direct({chain_id_to_use})"

            payload["paymentAuth"] = {"scheme": parsed.scheme, "proof": proof_ref, "chainId": str(chain_id_to_use)}
            headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        elif parsed.scheme == SchemeType.lnc_solana_transfer.value:
            if not self.solana_signer:
                raise PaymentExecutionError("lnc-solana-transfer 決済には solana_signer が必要です。")
            if not parsed.destination:
                raise PaymentExecutionError("HATEOAS Error: 'payTo' missing.")

            proof_ref = self.solana_signer.execute_x402_solana(parsed.amount, parsed.destination, parsed.reference)
            network_name = network_name if network_name != "UNKNOWN" else "Solana"
            
            # Solanaの要件: agentIdを含める
            agent_id = getattr(self, "agent_id", "Anonymous")
            payload["paymentAuth"] = {"scheme": parsed.scheme, "proof": proof_ref, "agentId": agent_id}
            headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        elif parsed.scheme in [SchemeType.L402.value, SchemeType.MPP.value, SchemeType.PAYMENT.value]:
            if not self.ln_adapter:
                raise PaymentExecutionError(f"{parsed.scheme} 決済には ln_adapter が必要です。")
            if not parsed.invoice:
                raise InvoiceParseError("Invoice not found in 402 challenge header.")

            proof_ref = self.ln_adapter.pay_invoice(parsed.invoice)
            network_name = "Lightning"
            
            if parsed.scheme == SchemeType.L402.value:
                if not parsed.macaroon:
                    raise InvoiceParseError("Macaroon not found.")
                headers["Authorization"] = f"L402 {parsed.macaroon}:{proof_ref}"
            else:
                charge_id = parsed.charge_id or "unknown_charge"
                headers["Authorization"] = f"Payment {charge_id}:{proof_ref}"
        else:
            raise PaymentExecutionError(f"Unsupported payment scheme: {parsed.scheme}")

        return proof_ref, network_name

    # ==========================================
    # v1.3.0: Execution Contract の強化 (同期 Runtime Layer)
    # ==========================================
    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        """[後方互換性維持] 内部で execute_detailed を呼び出し、レスポンスの辞書のみを返却する。"""
        result = self.execute_detailed(method, endpoint_path, payload, headers)
        return result.response

    # ==========================================
    # 同期 (Sync) Runtime Layer
    # ==========================================
    def execute_detailed(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, 
        _current_hop: int = 0, _payment_retry_count: int = 0,
        context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None
    ) -> ExecutionResult:
        
        # ★ v1.5.1: Contextが未指定の場合、フロー全体で同一のセッションを維持するためにここで初期化
        context = context or ExecutionContext()
        
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
            resp_data = {"status": "success", "message": "No content returned"} if not res.content else res.json()
            result = ExecutionResult(response=resp_data, final_url=url, retry_count=_payment_retry_count)
            
            if outcome_matcher:
                sig = inspect.signature(outcome_matcher)
                if len(sig.parameters) == 3:
                    result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                else:
                    result.outcome = outcome_matcher(resp_data, context)
            return result

        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries:
                raise PaymentExecutionError("Max 402 retries exceeded")
            
            parsed = self._parse_challenge(res, payload.get("asset", "SATS"))
            self._enforce_policy(parsed, url)

            # ★ 修正: sync 側も context.past_evidence を主経路にする (hints 代入をやめる)
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
            try:
                # Trust Evaluation
                for evaluator in self.trust_evaluators:
                    sig = inspect.signature(evaluator)
                    if len(sig.parameters) == 2:
                        decision = evaluator(evidence, context)
                    else:
                        decision = evaluator(url, parsed, context)
                    
                    if not decision.is_trusted:
                        raise CounterpartyTrustError(f"Trust Evaluation Blocked Payment: {decision.reason}")

                # Payment Execution
                proof_ref, network_name = self._process_payment(parsed, headers, payload)
                self._record_session_spend(parsed)

                receipt = SettlementReceipt(
                    scheme=parsed.scheme, network=network_name, asset=parsed.asset,
                    settled_amount=parsed.amount, proof_reference=proof_ref,
                    verification_status="verified" if network_name == "Lightning" else "self_reported"
                )
                self.last_receipt = receipt

                # Recursion
                next_result = self.execute_detailed(
                    method, url, payload, headers, _current_hop, _payment_retry_count + 1,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=receipt
                )
                
                next_result.settlement_receipt = receipt
                next_result.used_scheme = parsed.scheme
                next_result.used_asset = parsed.asset
                next_result.verification_status = receipt.verification_status
                
                # ★ v1.5.1: 正常完了時の Evidence Export
                if self.evidence_repo:
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                        trust_decision=decision,
                        receipt_summary={"receipt_id": receipt.receipt_id, "verification_status": receipt.verification_status},
                        outcome=next_result.outcome
                    )
                    self.evidence_repo.export_evidence(record, context)

                return next_result

            except Exception as e:
                # ★ v1.5.1: エラー時（Trust Block等）の Evidence Export
                if self.evidence_repo:
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                        trust_decision=decision, error_message=str(e)
                    )
                    self.evidence_repo.export_evidence(record, context)
                raise

        try:
            error_data = res.json()
            next_action = HateoasErrorResponse(**error_data).next_action
        except Exception:
            raise PaymentExecutionError(f"HTTP {res.status_code}: {res.text}")

        # 🟡 HATEOAS Navigation
        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            if next_method != "GET" and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")
            elif next_url and next_method != "NONE":
                # ★ HATEOASペイロードのスキームも正規化する安全装置
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                
                # ★ v1.5: context, outcome_matcher, receipt を引き継ぐ
                return self.execute_detailed(
                    next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=_current_receipt
                )

        raise PaymentExecutionError(f"API Error {res.status_code}: {error_data.get('message', res.text)}")

    # ==========================================
    # ⚡ 非同期 (Async) Runtime Layer
    # ==========================================
    async def execute_request_async(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        """[後方互換性維持] 内部で execute_detailed_async を呼び出し、レスポンスの辞書のみを返却する。"""
        result = await self.execute_detailed_async(method, endpoint_path, payload, headers)
        return result.response

    async def execute_detailed_async(
        self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, 
        _current_hop: int = 0, _payment_retry_count: int = 0,
        context: Optional[ExecutionContext] = None,
        outcome_matcher: Optional[Callable] = None,
        _current_receipt: Optional[SettlementReceipt] = None # v1.5: Matcherに渡すための内部状態
    ) -> ExecutionResult:
        """v1.3.0+: 確定的な実行結果オブジェクトを返す正式な非同期Runtimeメソッド。"""
        
        # ★ v1.5.1: Contextが未指定の場合、フロー全体で同一のセッションを維持するためにここで初期化
        context = context or ExecutionContext()
        
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

        # v1.3.1: 非同期クライアントの再利用
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(follow_redirects=True)

        res = await self._async_client.request(method_upper, url, **req_kwargs)

        # 🟢 Outcome Verification (200 OK)
        if 200 <= res.status_code < 300:
            resp_data = {"status": "success", "message": "No content returned"} if not res.content else res.json()
            result = ExecutionResult(response=resp_data, final_url=url, retry_count=_payment_retry_count)
            
            # v1.5: 決済後の結果（Outcome）を意味づけする（Provider-Agnostic）
            if outcome_matcher:
                sig = inspect.signature(outcome_matcher)
                if len(sig.parameters) == 3:
                    # v1.5 Signature: (response, receipt, context)
                    result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                else:
                    # v1.4 Fallback Signature: (response, context)
                    result.outcome = outcome_matcher(resp_data, context)
                    
            return result

        # 🔴 Counterparty Trust Evaluation (402 Payment Required)
        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries: 
                raise PaymentExecutionError("Max 402 retries exceeded")
            
            parsed = self._parse_challenge(res, payload.get("asset", "SATS"))
            self._enforce_policy(parsed, url)

            if getattr(self, "evidence_repo", None):
                if hasattr(self.evidence_repo, "import_evidence_async"):
                    past_records = await self.evidence_repo.import_evidence_async(url, context)
                else:
                    past_records = self.evidence_repo.import_evidence(url, context)
                
                if past_records:
                    # 修正: Magic Stringを排除し、型安全な専用フィールドへ格納
                    context.past_evidence = past_records

            # v1.5: TrustEvidence の構築（Source-Agnostic）
            evidence = TrustEvidence(
                url=url,
                challenge=parsed,
                host_metadata={},
                agent_hints=context.hints # hints はそのまま補助用として渡す
            )

            decision = None
            try:
                # 支払い前に相手の信用度を評価する
                for evaluator in self.trust_evaluators:
                    sig = inspect.signature(evaluator)
                    if len(sig.parameters) == 2:
                        decision = evaluator(evidence, context)
                    else:
                        decision = evaluator(url, parsed, context)
                    
                    if not decision.is_trusted:
                        raise CounterpartyTrustError(f"Trust Evaluation Blocked Payment: {decision.reason}")

                # アダプターのブロッキング処理を回避するため、スレッドプールで実行
                loop = asyncio.get_running_loop()
                proof_ref, network_name = await loop.run_in_executor(
                    None, self._process_payment, parsed, headers, payload
                )

                self._record_session_spend(parsed)

                receipt = SettlementReceipt(
                    scheme=parsed.scheme, network=network_name, asset=parsed.asset,
                    settled_amount=parsed.amount, proof_reference=proof_ref,
                    verification_status="verified" if network_name == "Lightning" else "self_reported"
                )
                self.last_receipt = receipt

                # v1.5: context, outcome_matcher に加え、発行された receipt を次に渡す
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
                        outcome=next_result.outcome
                    )
                    if hasattr(self.evidence_repo, "export_evidence_async"):
                        await self.evidence_repo.export_evidence_async(record, context)
                    else:
                        self.evidence_repo.export_evidence(record, context)

                return next_result

            except Exception as e:
                if getattr(self, "evidence_repo", None):
                    record = PaymentEvidenceRecord(
                        session_id=context.session_id, correlation_id=context.correlation_id,
                        target_url=url, method=method, scheme=parsed.scheme, asset=parsed.asset, amount=parsed.amount,
                        trust_decision=decision, error_message=str(e)
                    )
                    if hasattr(self.evidence_repo, "export_evidence_async"):
                        await self.evidence_repo.export_evidence_async(record, context)
                    else:
                        self.evidence_repo.export_evidence(record, context)
                raise
        try:
            error_data = res.json()
            next_action = HateoasErrorResponse(**error_data).next_action
        except Exception:
            raise PaymentExecutionError(f"HTTP {res.status_code}: {res.text}")

        # 🟡 HATEOAS Navigation
        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            
            if next_method != "GET" and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")
            elif next_url and next_method != "NONE":
                # ★ HATEOASペイロードのスキームも正規化
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                await asyncio.sleep(1) 
                
                # ★ v1.5: context, outcome_matcher, receipt を引き継ぐ
                return await self.execute_detailed_async(
                    next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count,
                    context=context, outcome_matcher=outcome_matcher,
                    _current_receipt=_current_receipt
                )

        raise PaymentExecutionError(f"API Error {res.status_code}: {error_data.get('message', res.text)}")

    async def aclose(self):
        """v1.3.1: 非同期セッションを明示的に閉じるためのメソッド"""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    async def __aenter__(self):
        """v1.3.1: async with ブロックに入った時の処理"""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(follow_redirects=True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """v1.3.1: async with ブロックを抜けた時に自動でセッションを閉じる"""
        await self.aclose()

# ==========================================
# ⛩️ ADAPTER: LN Church 専用拡張クラス
# ==========================================
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
        # 1. v1.3.1: 親クラスを呼ぶ前に、鍵の検証と agent_id の導出を完了させる
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
                    # ここで確実に捕捉し、意図した ValueError を投げる
                    raise ValueError(
                        "Invalid private_key format. Could not parse as EVM hex or Solana Base58. "
                        f"Detailed error: {e}"
                    )
        else:
            derived_agent_id = agent_id or "Anonymous_Agent"


        # ★ 修正: 親クラスの初期化（下層アダプタの生成）で発生するパースエラーを捕捉し、
        # LnChurchClient として意図したエラーメッセージに正規化（バブリング順の調整）
        try:
            # 🚨 修正: 必要な引数をすべて親クラスにしっかり引き継ぐ！
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
            # LocalKeyAdapter や LocalSolanaAdapter が発した ValueError をキャッチし、
            # テストが期待する "Invalid private_key format ..." に統一して投げ直す
            raise ValueError(f"Invalid private_key format. Details: {str(e)}") from e

        # 3. 導出したIDと初期プロパティをセット
        self.agent_id = derived_agent_id
        self.probe_token = None
        self.faucet_token = None

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


    # ------------------------------------------
    # 同期 (Sync) メソッド群: Convenience Defaults 修正
    # ------------------------------------------
    def init_probe(self):
        res = self.execute_request("GET", f"/api/agent/probe?agentId={self.agent_id}&src=sdk")
        self.probe_token = res.get("capability_receipt", {}).get("token") or res.get("probe_token")
        print("[System] Probe Completed.")

    def claim_faucet_if_empty(self):
        try:
            res = self.execute_request("POST", "/api/agent/faucet", {"agentId": self.agent_id})
            self.faucet_token = res.get("grant_token")
            print("[System] Faucet Claimed.")
        except Exception as e:
            print(f"[System] Faucet skipped or failed: {str(e)}")


    def draw_omikuji(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> OmikujiResponse:
        # デフォルトは旗艦導線の 'L402' (非SATSの場合は市場標準の 'x402')
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        return OmikujiResponse(**self.execute_request("POST", "/api/agent/omikuji", payload, headers))

    def submit_confession(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None) -> ConfessionResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        return ConfessionResponse(**self.execute_request("POST", "/api/agent/confession", payload))

    def offer_hono(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> HonoResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value, "amount": amount}
        return HonoResponse(**self.execute_request("POST", "/api/agent/hono", payload))

    def issue_identity(self) -> AgentIdentity:
        res = self.execute_request("POST", "/api/agent/identity/issue", {"agentId": self.agent_id})
        return AgentIdentity(status=res["status"], public_profile_url=res["public_profile_url"], agent_id=self.agent_id)

    def resolve_identity(self, target_agent_id: str = None) -> AgentIdentity:
        target_id = target_agent_id or self.agent_id
        res = self.execute_request("GET", f"/api/agent/identity/{target_id}")
        return AgentIdentity(**res)

    def get_benchmark_overview(self) -> BenchmarkOverviewResponse:
        return BenchmarkOverviewResponse(**self.execute_request("GET", f"/api/agent/benchmark/{self.agent_id}"))

    def compare_trial_performance(self, trial_id: str, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> CompareResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        return CompareResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload))

    def request_fast_pass_aggregate(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> AggregateResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        return AggregateResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{self.agent_id}/aggregate", payload))

    def submit_monzen_trace(self, target_url: str, invoice: str, preimage: Optional[str] = None, method: str = "POST", scheme: Optional[str] = None) -> MonzenTraceResponse: 
        payload = {"agentId": self.agent_id, "targetUrl": target_url, "invoice": invoice, "method": method}
        if preimage: payload["preimage"] = preimage
        if scheme: payload["scheme"] = scheme
        res_dict = self.execute_request("POST", "/api/agent/monzen/trace", payload)
        return MonzenTraceResponse(**res_dict)

    def get_site_metrics(self, limit: int = 10, target_agent_id: Optional[str] = None, scheme: Optional[str] = None) -> MonzenMetricsResponse:
        params = {"limit": limit}
        if target_agent_id: params["agentId"] = target_agent_id
        if scheme: params["scheme"] = scheme
        return MonzenMetricsResponse(**self.execute_request("GET", "/api/agent/monzen/metrics", payload=params))

    def download_monzen_graph(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> MonzenGraphResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        # (Solanaの場合は明示指定で 'lnc-solana-transfer' を使うようドキュメントで誘導)
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        res = self.execute_request("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)

    # ------------------------------------------
    # ⚡ 非同期 (Async) メソッド群: Convenience Defaults 修正
    # ------------------------------------------
    async def init_probe_async(self):
        res = await self.execute_request_async("GET", f"/api/agent/probe?agentId={self.agent_id}&src=sdk_async")
        self.probe_token = res.get("capability_receipt", {}).get("token") or res.get("probe_token")
        print("[System ASYNC] Probe Completed.")

    async def claim_faucet_if_empty_async(self):
        try:
            res = await self.execute_request_async("POST", "/api/agent/faucet", {"agentId": self.agent_id})
            self.faucet_token = res.get("grant_token")
            print("[System ASYNC] Faucet Claimed.")
        except Exception as e:
            print(f"[System ASYNC] Faucet skipped or failed: {str(e)}")

    async def draw_omikuji_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> OmikujiResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        res = await self.execute_request_async("POST", "/api/agent/omikuji", payload, headers)
        return OmikujiResponse(**res)

    async def submit_confession_async(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None) -> ConfessionResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", "/api/agent/confession", payload)
        return ConfessionResponse(**res)

    async def offer_hono_async(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> HonoResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value, "amount": amount}
        res = await self.execute_request_async("POST", "/api/agent/hono", payload)
        return HonoResponse(**res)

    async def issue_identity_async(self) -> AgentIdentity:
        res = await self.execute_request_async("POST", "/api/agent/identity/issue", {"agentId": self.agent_id})
        return AgentIdentity(status=res["status"], public_profile_url=res["public_profile_url"], agent_id=self.agent_id)

    async def resolve_identity_async(self, target_agent_id: str = None) -> AgentIdentity:
        target_id = target_agent_id or self.agent_id
        res = await self.execute_request_async("GET", f"/api/agent/identity/{target_id}")
        return AgentIdentity(**res)

    async def get_benchmark_overview_async(self) -> BenchmarkOverviewResponse:
        res = await self.execute_request_async("GET", f"/api/agent/benchmark/{self.agent_id}")
        return BenchmarkOverviewResponse(**res)

    async def compare_trial_performance_async(self, trial_id: str, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> CompareResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload)
        return CompareResponse(**res)

    async def request_fast_pass_aggregate_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> AggregateResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", f"/api/agent/benchmark/trials/{self.agent_id}/aggregate", payload)
        return AggregateResponse(**res)

    async def submit_monzen_trace_async(self, target_url: str, invoice: str, preimage: Optional[str] = None, method: str = "POST",scheme: Optional[str] = None) -> MonzenTraceResponse: 
        payload = {"agentId": self.agent_id, "targetUrl": target_url, "invoice": invoice, "method": method}
        if preimage: payload["preimage"] = preimage
        if scheme: payload["scheme"] = scheme
        res_dict = await self.execute_request_async("POST", "/api/agent/monzen/trace", payload)
        return MonzenTraceResponse(**res_dict)

    async def get_site_metrics_async(self, limit: int = 10, target_agent_id: Optional[str] = None, scheme: Optional[str] = None) -> MonzenMetricsResponse:
        params = {"limit": limit}
        if target_agent_id: params["agentId"] = target_agent_id
        if scheme: params["scheme"] = scheme
        res = await self.execute_request_async("GET", "/api/agent/monzen/metrics", payload=params)
        return MonzenMetricsResponse(**res)

    async def download_monzen_graph_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> MonzenGraphResponse:
        # デフォルトは標準仕様のx402 / L402を維持
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        res = await self.execute_request_async("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)