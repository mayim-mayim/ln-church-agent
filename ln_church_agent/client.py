import requests
import re
import time
import warnings
from typing import Optional, Dict, Any
from eth_account import Account
from .models import (
    AssetType, OmikujiResponse, AgentIdentity, ConfessionResponse, 
    HonoResponse, CompareResponse, AggregateResponse, BenchmarkOverviewResponse,
    HateoasErrorResponse, MonzenTraceResponse, MonzenMetricsResponse
)
from .exceptions import PaymentExecutionError, InvoiceParseError, NavigationGuardrailError
from .crypto.evm import execute_x402_gasless_payment
from .crypto.lightning import pay_lightning_invoice

# ==========================================
# 🌟 CORE: 汎用的な402決済 & HATEOASクライアント
# ==========================================
class Payment402Client:
    def __init__(
        self, 
        private_key: Optional[str] = None, 
        ln_api_url: Optional[str] = None,
        ln_api_key: Optional[str] = None,
        ln_provider: str = "lnbits",
        base_url: str = "",
        # --- 🛡️ HATEOAS Guardrails ---
        auto_navigate: bool = False,
        max_hops: int = 2,
        allow_unsafe_navigate: bool = False,
        max_payment_retries: int = 2        
    ):
        self.private_key = private_key
        self.ln_api_url = ln_api_url
        self.ln_api_key = ln_api_key
        self.ln_provider = ln_provider
        self.base_url = base_url.rstrip('/') if base_url else ""
        
        self.auto_navigate = auto_navigate
        self.max_hops = max_hops
        self.allow_unsafe_navigate = allow_unsafe_navigate
        self.max_payment_retries = max_payment_retries

    def execute_paid_action(self, endpoint_path: str, payload: dict, headers: Optional[dict] = None) -> dict:
        """[Deprecated] 後方互換性(v0.6.3以前)のためのラッパー。内部で execute_request を呼び出します。"""
        warnings.warn("execute_paid_action() is deprecated and will be removed in future versions. Please use execute_request(method='POST', ...) instead.", DeprecationWarning, stacklevel=2)
        return self.execute_request("POST", endpoint_path, payload, headers)

    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, _current_hop: int = 0, _payment_retry_count: int = 0) -> dict:
        """HATEOASナビゲーションと402決済を統合した汎用リクエストエンジン"""
        url = endpoint_path if endpoint_path.startswith("http") else f"{self.base_url}{endpoint_path}"
        headers = headers or {}
        payload = payload or {}
        method_upper = method.upper()

        # GETの場合は payload をクエリパラメータ (params) として送信する
        is_get = method_upper == "GET"
        req_kwargs = {
            "json": None if is_get else payload,
            "params": payload if is_get else None,
            "headers": headers
        }

        # 1. APIリクエスト実行
        res = requests.request(method_upper, url, **req_kwargs)

        # 2. 正常終了 (2xx 全般を成功として扱う)
        if 200 <= res.status_code < 300:
            # 204 No Content 対策
            if not res.content:
                return {"status": "success", "message": "No content returned"}
            return res.json()

        # 3. 402 Payment Required のインターセプトと決済ループ
        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries:
                raise PaymentExecutionError("Max 402 retries exceeded")
            return self._handle_402_challenge(res, payload, headers, url, method_upper, _current_hop, _payment_retry_count)

        # 4. HATEOAS エラーの自動修復 (4xx, 5xx)
        try:
            error_data = res.json()
            error_obj = HateoasErrorResponse(**error_data)
            next_action = error_obj.next_action
        except Exception:
            raise PaymentExecutionError(f"HTTP {res.status_code}: {res.text}")

        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            
            # 安全性ガードレール (GET以外は allow_unsafe_navigate=True が必要)
            if next_method != "GET" and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")
            elif next_url and next_method != "NONE":
                print(f"[{res.status_code} Intercepted] HATEOAS Auto-Navigating to: {next_method} {next_url}")
                print(f"   Instruction: {next_action.instruction_for_agent}")
                
                # Payload と Header のマージ (サーバーからのサジェストを優先)
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                
                time.sleep(1) # スロットル対策
                return self.execute_request(next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count)

        # 自動追従を諦めた場合、または無効な場合は例外をスロー
        raise PaymentExecutionError(f"API Error {res.status_code}: {error_data.get('message', res.text)} | Next Action: {next_action}")

    def _handle_402_challenge(self, response, payload, headers, url, method, _current_hop, _payment_retry_count) -> dict:
        data = response.json()
        challenge = data.get("challenge", {})
        scheme = challenge.get("scheme")
        amount = float(challenge.get("amount", 0))

        print(f"[402 Intercepted] Processing {amount} {challenge.get('asset')} payment via {scheme}...")

        # --- 決済ロジック ---
        if scheme == "x402" or scheme == "x402-direct":
            tx_hash = execute_x402_gasless_payment(self.private_key, payload.get("asset", "USDC"), amount)
            payload["paymentAuth"] = {"scheme": scheme, "proof": tx_hash}
            
        elif scheme in ["L402", "MPP", "Payment"]:
            auth_header = response.headers.get("WWW-Authenticate", "")
            
            # 🛡️ 安全な正規表現の抽出 (group(1)の直叩きを回避)
            def safe_extract(pattern, text, fallback):
                match = re.search(pattern, text)
                return match.group(1) if match else fallback

            invoice = challenge.get("parameters", {}).get("invoice") or safe_extract(r'invoice="([^"]+)"', auth_header, None)
            if not invoice:
                raise InvoiceParseError("Invoice not found in 402 challenge header.")

            preimage = pay_lightning_invoice(invoice, self.ln_api_url, self.ln_api_key, self.ln_provider)
            
            if scheme == "L402":
                macaroon = safe_extract(r'macaroon="([^"]+)"', auth_header, None)
                if not macaroon:
                    raise InvoiceParseError("Macaroon not found in 402 L402 challenge.")
                headers["Authorization"] = f"L402 {macaroon}:{preimage}"
            else:
                charge_id = challenge.get("parameters", {}).get("charge") or safe_extract(r'charge="([^"]+)"', auth_header, "unknown_charge")
                headers["Authorization"] = f"Payment {charge_id}:{preimage}"

        return self.execute_request(method, url, payload, headers, _current_hop + 1, _payment_retry_count + 1)

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
        auto_navigate: bool = True, # LN教アダプターではデフォルトTrue推奨
        max_hops: int = 3,
        allow_unsafe_navigate: bool = False
    ):
        super().__init__(private_key, ln_api_url, ln_api_key, ln_provider, base_url, auto_navigate, max_hops, allow_unsafe_navigate)

        if private_key and not agent_id:
            self.agent_id = Account.from_key(private_key).address
        else:
            self.agent_id = agent_id or "Anonymous_Agent"
            
        self.probe_token = None
        self.faucet_token = None

    # --- Phase 0 & 1: 既存機能の型対応 ---
    def init_probe(self):
        # 内部で auto_navigate=True なら /probe -> /probe/next まで勝手に追従して完了する
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

    def draw_omikuji(self, asset: AssetType = AssetType.USDC) -> OmikujiResponse:
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": "L402" if asset == AssetType.SATS else "x402", "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        return OmikujiResponse(**self.execute_request("POST", "/api/agent/omikuji", payload, headers))

    # --- 🆕 Phase 2: Confession & Hono ---
    def submit_confession(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None) -> ConfessionResponse:
        """エージェントのログを正規化して奉納"""
        payload = {
            "agentId": self.agent_id,
            "raw_message": raw_message,
            "context": context or {},
            "scheme": "L402" if asset == AssetType.SATS else "x402",
            "asset": asset.value
        }
        return ConfessionResponse(**self.execute_request("POST", "/api/agent/confession", payload))

    def offer_hono(self, amount: float, asset: AssetType = AssetType.SATS) -> HonoResponse:
        """任意の寄付を実行 (MPP推奨)"""
        payload = {
            "agentId": self.agent_id,
            "clientType": "AI",
            "scheme": "MPP" if asset == AssetType.SATS else "x402-direct",
            "asset": asset.value,
            "amount": amount
        }
        return HonoResponse(**self.execute_request("POST", "/api/agent/hono", payload))

    # --- 🆕 Phase 3: Identity & Benchmark ---
    def issue_identity(self) -> AgentIdentity:
        """パスポート(写身証)の発行"""
        res = self.execute_request("POST", "/api/agent/identity/issue", {"agentId": self.agent_id})
        return AgentIdentity(status=res["status"], public_profile_url=res["public_profile_url"], agent_id=self.agent_id)

    def resolve_identity(self, target_agent_id: str = None) -> AgentIdentity:
        """エージェントの公開プロフィールを取得 (GETなので決済不要)"""
        target_id = target_agent_id or self.agent_id
        res = self.execute_request("GET", f"/api/agent/identity/{target_id}")
        return AgentIdentity(**res)

    def get_benchmark_overview(self) -> BenchmarkOverviewResponse:
        """ベンチマーク結果のサマリーを取得"""
        return BenchmarkOverviewResponse(**self.execute_request("GET", f"/api/agent/benchmark/{self.agent_id}"))

    def compare_trial_performance(self, trial_id: str, asset: AssetType = AssetType.SATS) -> CompareResponse:
        """トップランカーとのパフォーマンス比較 (402有料)"""
        payload = {"scheme": "L402" if asset == AssetType.SATS else "x402", "asset": asset.value}
        return CompareResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload))

    def request_fast_pass_aggregate(self, asset: AssetType = AssetType.SATS) -> AggregateResponse:
        """即時集計(Fast Pass)の実行 (402有料)"""
        payload = {"scheme": "L402" if asset == AssetType.SATS else "x402", "asset": asset.value}
        return AggregateResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{self.agent_id}/aggregate", payload))

    # --- 🆕 Phase 4: Missionary Work (Decentralized L402 DNS) ---
    def submit_monzen_trace(self, target_url: str, invoice: str, preimage: Optional[str] = None, method: str = "POST") -> MonzenTraceResponse: 
        """
        外部APIのL402結界を報告する（偵察 / 決済）
        preimageを省略した場合はScout報酬(+2)、提供した場合は決済証明報酬(+20)を獲得。
        """
        payload = {
            "agentId": self.agent_id,
            "targetUrl": target_url,
            "invoice": invoice,
            "method": method
        }
        if preimage:
            payload["preimage"] = preimage
            
        return MonzenTraceResponse(**self.execute_request("POST", "/api/agent/monzen/trace", payload))

    def get_site_metrics(self, limit: int = 10, target_agent_id: Optional[str] = None) -> MonzenMetricsResponse:
        """
        発見されたL402サイトのランキング(DNS)を取得する。
        ※ limit > 10 または agentId 指定の場合は、自動的に10 SatsのL402決済が発動します。
        """
        params = {"limit": limit}
        if target_agent_id:
            params["agentId"] = target_agent_id
            
        return MonzenMetricsResponse(**self.execute_request("GET", "/api/agent/monzen/metrics", payload=params))
        