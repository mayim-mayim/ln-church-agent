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
    ChallengeSource, AttestationSource
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

def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("ln-church-agent")
    except importlib.metadata.PackageNotFoundError:
        return "1.5.7" 

SDK_VERSION = get_sdk_version()
CUSTOM_USER_AGENT = f"ln-church-agent/{get_sdk_version()}"

# base64対応
def _b64url_decode(b64_str: str) -> dict:
    """Base64URL文字列をデコードしてJSON辞書として返す安全なヘルパー"""
    try:
        # 足りないパディング(=)を自動補完
        padded = b64_str + '=' * (-len(b64_str) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded_bytes.decode('utf-8'))
    except Exception:
        return {}

def _b64url_encode(data_dict: dict) -> str:
    """JSON辞書をBase64URL文字列（パディングなし）にエンコードするヘルパー"""
    json_str = json.dumps(data_dict)
    b64_bytes = base64.urlsafe_b64encode(json_str.encode('utf-8'))
    return b64_bytes.decode('utf-8').rstrip('=')

# 内部用のレガシーSchemeマッピングヘルパー
# ⛩️ 本殿の新しい命名規則（語彙体系）へ追随
def _normalize_scheme(raw_scheme: str) -> str:
    s = raw_scheme.lower()
    # 独自仕様のレガシーエイリアスを正規化
    if s == "x402-direct": return SchemeType.lnc_evm_transfer.value
    if s == "x402-solana": return SchemeType.lnc_solana_transfer.value
    if s == "x402-relay":  return SchemeType.lnc_evm_relay.value
    
    # 'x402' は標準仕様 (Foundation準拠) としてそのまま通す
    if s == "x402": return SchemeType.x402.value
    
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
    def _parse_challenge(self, response: httpx.Response, expected_asset: str = "USDC") -> ParsedChallenge:
        h = response.headers
        
        # ★ 1. Lightning系 (L402/MPP) を最優先で処理
        # Dual-Stack環境では PAYMENT-REQUIRED よりも、インボイスを含むこちらが重要
        auth_h = h.get("WWW-Authenticate", "")
        if auth_h.upper().startswith(("L402", "PAYMENT", "MPP")):
            return self._parse_www_authenticate(auth_h, source=ChallengeSource.STANDARD_WWW)

        # ★ 2. x402系 (PAYMENT-REQUIRED)
        if "PAYMENT-REQUIRED" in h:
            val = h["PAYMENT-REQUIRED"]
            # 新標準 (Base64 JSON) か 旧レガシー (network="..." 文字列) か判定
            if not val.startswith('network='):
                payload = _b64url_decode(val)
                if payload:
                    params = {
                        "network": payload.get("network", "unknown"),
                        "amount": payload.get("amount", 0),
                        "asset": payload.get("asset", expected_asset),
                        "destination": payload.get("destination", ""),
                        "challenge": payload.get("challenge", "")
                    }
                    # 念のためボディからも不足パラメータを補完
                    try:
                        body_params = response.json().get("challenge", {}).get("parameters", {})
                        params.update(body_params)
                    except Exception:
                        pass

                    return ParsedChallenge(
                        scheme=payload.get("scheme", "x402"),
                        network=params["network"],
                        amount=float(params["amount"]),
                        asset=params["asset"],
                        parameters=params,
                        source=ChallengeSource.STANDARD_X402,
                        raw_header=val
                    )
            
            # フォールバック: レガシー文字列パース
            params = {k: v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', val)}
            
            # ★ 修正: レガシー文字列には destination が含まれないためボディから取得
            try:
                body_params = response.json().get("challenge", {}).get("parameters", {})
                params.update(body_params)
            except Exception:
                pass

            return ParsedChallenge(
                scheme=params.get("scheme", "x402"),
                network=params.get("network", "unknown"),
                amount=float(params.get("amount", 0)),
                asset=params.get("asset", expected_asset),
                parameters=params,
                source=ChallengeSource.STANDARD_X402,
                raw_header=val
            )

        # 3. フォールバック: レスポンスボディ (LN教旧仕様)
        try:
            body = response.json()
            if "challenge" in body:
                c = body["challenge"]
                return ParsedChallenge(
                    scheme=c.get("scheme"),
                    network=c.get("network"),
                    amount=float(c.get("amount", 0)),
                    asset=c.get("asset"),
                    parameters=c.get("parameters", {}),
                    source=ChallengeSource.BODY_CHALLENGE
                )
        except Exception:
            pass

        # 4. 最終手段: 旧カスタムヘッダー
        if "x-402-payment-required" in h:
            return self._parse_legacy_header(h["x-402-payment-required"])

        raise PaymentChallengeError("No valid 402 challenge found in headers or body.")

    def _parse_www_authenticate(self, auth_header: str, source: ChallengeSource) -> ParsedChallenge:
        """WWW-Authenticate (L402 / MPP) ヘッダーのパース処理"""
        parts = auth_header.split(" ", 1)
        scheme = parts[0]
        params = {}
        if len(parts) > 1:
            params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', parts[1])}
            
        return ParsedChallenge(
            scheme=scheme,
            network="Lightning", # デフォルトネットワーク
            amount=0.0,          # 通常L402はインボイス内に金額が含まれるため0とする
            asset="SATS",
            parameters=params,
            source=source,
            raw_header=auth_header
        )

    def _parse_legacy_header(self, header_val: str) -> ParsedChallenge:
        """旧カスタムヘッダー (x-402-payment-required) のパース処理"""
        params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', header_val)}
        return ParsedChallenge(
            scheme=params.get("scheme", "unknown"),
            network=params.get("network", "unknown"),
            amount=float(params.get("amount", 0)),
            asset=params.get("asset", "USDC"),
            parameters=params,
            source=ChallengeSource.LEGACY_CUSTOM,
            raw_header=header_val
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
        if parsed.scheme not in self.policy.allowed_schemes:
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
        network_name = parsed.network or "UNKNOWN"

        # 1. EVM系 (x402, lnc-evm-*) の処理
        if parsed.scheme in [SchemeType.x402.value, SchemeType.lnc_evm_relay.value, SchemeType.lnc_evm_transfer.value]:
            if not self.evm_signer:
                raise PaymentExecutionError(f"{parsed.scheme} 決済には evm_signer が必要です。")
            
            # 宛先等の取得 (ParsedChallenge.parameters 経由)
            dest = parsed.parameters.get("destination") or parsed.parameters.get("payTo")
            if not dest:
                raise PaymentExecutionError("HATEOAS Error: Treasury address is missing.")

            chain_id_to_use = 137
            if parsed.parameters.get("chain_id"):
                chain_id_to_use = int(parsed.parameters.get("chain_id"))
            elif parsed.network.startswith("eip155:"):
                chain_id_to_use = int(parsed.network.split(":")[1])

            # 実際の執行
            if parsed.scheme == SchemeType.lnc_evm_transfer.value:
                proof_ref = self.evm_signer.execute_lnc_evm_transfer_settlement(
                    parsed.asset, parsed.amount, dest, chain_id_to_use, 
                    parsed.parameters.get("token_address"), self.evm_rpc_url
                )
            else:
                # 標準 x402 または lnc-evm-relay (ガスレス)
                if parsed.scheme == SchemeType.x402.value:
                    from .crypto.evm import sign_standard_x402_evm
                    proof_ref = sign_standard_x402_evm(self.private_key, parsed)
                else:
                    proof_ref = self.evm_signer.execute_lnc_evm_relay_settlement(
                        parsed.asset, parsed.amount, parsed.parameters.get("relayer_endpoint"), 
                        dest, chain_id_to_use, parsed.parameters.get("token_address")
                    )

            # 【★重要: Dual Stack リトライの構成】
            if parsed.scheme == SchemeType.x402.value:
                # ★ 新標準: Base64 JSON Payload の構築
                payment_payload = {
                    "proof": proof_ref,
                    "challenge": parsed.parameters.get("challenge", "")
                }
                headers["PAYMENT-SIGNATURE"] = _b64url_encode(payment_payload)
            
            # LN教互換用ボディ (全EVM系で付与)
            # 標準 x402 の場合はペイロード（ボディ）を汚染せず、レガシー拡張ルートのみ付与する
            if parsed.scheme != SchemeType.x402.value:
                payload["paymentAuth"] = {
                    "scheme": parsed.scheme, 
                    "proof": proof_ref, 
                    "chainId": str(chain_id_to_use),
                    "standard_x402": False
                }
            # 互換用 Authorization ヘッダー
            headers["Authorization"] = f"{parsed.scheme} {proof_ref}"

        # 2. Solana系の処理
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

        # 3. Lightning系 (L402, MPP) の処理
        elif parsed.scheme in [SchemeType.l402.value, SchemeType.mpp.value, "Payment"]:
            if not self.ln_adapter:
                raise PaymentExecutionError(f"{parsed.scheme} 決済には ln_adapter が必要です。")
            invoice = parsed.parameters.get("invoice")
            if not invoice:
                raise InvoiceParseError("Challenge にインボイスが含まれていません。")

            proof_ref = self.ln_adapter.pay_invoice(invoice)
            
            if parsed.scheme == SchemeType.l402.value:
                mac = parsed.parameters.get("macaroon")
                headers["Authorization"] = f"L402 {mac}:{proof_ref}"
            else:
                charge_id = parsed.parameters.get("charge")
                if charge_id:
                    headers["Authorization"] = f"{parsed.scheme} {charge_id}:{proof_ref}"
                else:
                    headers["Authorization"] = f"{parsed.scheme} {proof_ref}"
        return proof_ref, network_name

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
            
            raw_response = res.headers.get("PAYMENT-RESPONSE")
            token = None
            if raw_response:
                if not raw_response.startswith('status='):
                    payload = _b64url_decode(raw_response)
                    token = payload.get("receipt") if payload else raw_response
                else:
                    match = re.search(r'receipt="?([^",]+)"?', raw_response)
                    token = match.group(1) if match else raw_response
            else:
                token = res.headers.get("Payment-Receipt")

            if token and _current_receipt:
                _current_receipt.receipt_token = token
                _current_receipt.source = AttestationSource.SERVER_JWS
                _current_receipt.verification_status = "verified"
            
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

                proof_ref, network_name = self._process_payment(parsed, headers, payload)
                self._record_session_spend(parsed)

                receipt = SettlementReceipt(
                    receipt_id=str(uuid.uuid4()),
                    scheme=parsed.scheme, network=network_name, asset=parsed.asset,
                    settled_amount=parsed.amount, proof_reference=proof_ref,
                    verification_status="verified" if network_name == "Lightning" else "self_reported"
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
                        outcome=next_result.outcome
                    )
                    self.evidence_repo.export_evidence(record, context)

                return next_result

            except Exception as e:
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
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                
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

        if self._async_client is None:
            self._async_client = httpx.AsyncClient(follow_redirects=True)

        res = await self._async_client.request(method_upper, url, **req_kwargs)

        # 🟢 Outcome Verification (200 OK)
        if 200 <= res.status_code < 300:
            resp_data = {"status": "success", "message": "No content returned"} if not res.content else res.json()
            result = ExecutionResult(response=resp_data, final_url=url, retry_count=_payment_retry_count)
            
            raw_response = res.headers.get("PAYMENT-RESPONSE")
            token = None
            if raw_response:
                if not raw_response.startswith('status='):
                    payload = _b64url_decode(raw_response)
                    token = payload.get("receipt") if payload else raw_response
                else:
                    match = re.search(r'receipt="?([^",]+)"?', raw_response)
                    token = match.group(1) if match else raw_response
            else:
                token = res.headers.get("Payment-Receipt")

            if token and _current_receipt:
                _current_receipt.receipt_token = token
                _current_receipt.source = AttestationSource.SERVER_JWS
                _current_receipt.verification_status = "verified"
            
            if outcome_matcher:
                sig = inspect.signature(outcome_matcher)
                if len(sig.parameters) == 3:
                    result.outcome = outcome_matcher(resp_data, _current_receipt, context)
                else:
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
                    context.past_evidence = past_records

            evidence = TrustEvidence(
                url=url,
                challenge=parsed,
                host_metadata={},
                agent_hints=context.hints
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
                    receipt_id=str(uuid.uuid4()),
                    scheme=parsed.scheme, network=network_name, asset=parsed.asset,
                    settled_amount=parsed.amount, proof_reference=proof_ref,
                    verification_status="verified" if network_name == "Lightning" else "self_reported"
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
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                if "scheme" in merged_payload:
                    merged_payload["scheme"] = _normalize_scheme(merged_payload["scheme"])

                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                await asyncio.sleep(1) 
                
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
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        return OmikujiResponse(**self.execute_request("POST", "/api/agent/omikuji", payload, headers))

    def submit_confession(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None) -> ConfessionResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        return ConfessionResponse(**self.execute_request("POST", "/api/agent/confession", payload))

    def offer_hono(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> HonoResponse:
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
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        return CompareResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload))

    def request_fast_pass_aggregate(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> AggregateResponse:
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
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        res = await self.execute_request_async("POST", "/api/agent/omikuji", payload, headers)
        return OmikujiResponse(**res)

    async def submit_confession_async(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None) -> ConfessionResponse:
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", "/api/agent/confession", payload)
        return ConfessionResponse(**res)

    async def offer_hono_async(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> HonoResponse:
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
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload)
        return CompareResponse(**res)

    async def request_fast_pass_aggregate_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> AggregateResponse:
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
        target_scheme = scheme or (SchemeType.l402.value if asset == AssetType.SATS else SchemeType.x402.value)
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        res = await self.execute_request_async("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)