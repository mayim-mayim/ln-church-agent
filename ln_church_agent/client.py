import requests
import httpx
import re
import time
import asyncio
import warnings
import importlib.metadata
import uuid

from typing import Optional, Dict, Any
from eth_account import Account
from .models import (
    AssetType, OmikujiResponse, AgentIdentity, ConfessionResponse, 
    HonoResponse, CompareResponse, AggregateResponse, BenchmarkOverviewResponse,
    HateoasErrorResponse, MonzenTraceResponse, MonzenMetricsResponse,
    MonzenGraphResponse, PaymentPolicy, SettlementReceipt
)
from .exceptions import PaymentExecutionError, InvoiceParseError, NavigationGuardrailError

from .crypto.protocols import EVMSigner, LightningProvider

try:
    from .crypto.protocols import SolanaSigner
except ImportError:
    SolanaSigner = Any

def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("ln-church-agent")
    except importlib.metadata.PackageNotFoundError:
        return "1.2.3" 

SDK_VERSION = get_sdk_version()
CUSTOM_USER_AGENT = f"ln-church-agent/{get_sdk_version()}"

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
        evm_rpc_url: Optional[str] = None, 
        nwc_bridge_url: Optional[str] = None, 
        auto_navigate: bool = False,
        max_hops: int = 2,
        allow_unsafe_navigate: bool = False,
        max_payment_retries: int = 2,
        # --- v1.2.0 Boundaries ---
        nwc_uri: Optional[str] = None,
        policy: Optional[PaymentPolicy] = None,
        evm_signer: Optional[EVMSigner] = None,
        ln_adapter: Optional[LightningProvider] = None,
        solana_signer: Optional[SolanaSigner] = None,
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

        # [1] Policy & Receipt
        self.policy = policy or PaymentPolicy()
        self.last_receipt: Optional[SettlementReceipt] = None 

        # [2] Default Adapter Pattern
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

    def _enforce_policy(self, scheme: str, asset: str, amount: float):
        """決済実行前にPaymentPolicyを評価する強固なガードレール"""
        if not self.policy:
            return

        if scheme not in self.policy.allowed_schemes:
            raise PaymentExecutionError(f"Policy Violation: Scheme '{scheme}' is restricted.")
        if asset not in self.policy.allowed_assets:
            raise PaymentExecutionError(f"Policy Violation: Asset '{asset}' is restricted.")
        
        # 簡易的なUSD換算による上限チェック
        usd_value = 0.0
        if asset == "USDC":
            usd_value = amount
        elif asset == "JPYC":
            usd_value = amount * 0.0067
        elif asset == "SATS":
            usd_value = amount * 0.00065

        if usd_value > self.policy.max_spend_per_tx_usd:
            raise PaymentExecutionError(
                f"Policy Violation: Amount ({usd_value:.4f} USD equivalent) "
                f"exceeds max_spend_per_tx_usd ({self.policy.max_spend_per_tx_usd})."
            )

    def execute_paid_action(self, endpoint_path: str, payload: dict, headers: Optional[dict] = None) -> dict:
        warnings.warn("execute_paid_action() is deprecated. Please use execute_request(method='POST', ...) instead.", DeprecationWarning, stacklevel=2)
        return self.execute_request("POST", endpoint_path, payload, headers)

    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, _current_hop: int = 0, _payment_retry_count: int = 0) -> dict:
        url = endpoint_path if endpoint_path.startswith("http") else f"{self.base_url}{endpoint_path}"
        headers = dict(headers or {}) 
        
        if not any(k.lower() == "user-agent" for k in headers.keys()):
            headers["User-Agent"] = CUSTOM_USER_AGENT

        payload = payload or {}
        method_upper = method.upper()
        is_get = method_upper == "GET"
        req_kwargs = {
            "json": None if is_get else payload,
            "params": payload if is_get else None,
            "headers": headers
        }

        res = requests.request(method_upper, url, **req_kwargs)

        if 200 <= res.status_code < 300:
            if not res.content: return {"status": "success", "message": "No content returned"}
            return res.json()

        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries: raise PaymentExecutionError("Max 402 retries exceeded")
            return self._handle_402_challenge(res, payload, headers, url, method_upper, _current_hop, _payment_retry_count)

        try:
            error_data = res.json()
            error_obj = HateoasErrorResponse(**error_data)
            next_action = error_obj.next_action
        except Exception:
            raise PaymentExecutionError(f"HTTP {res.status_code}: {res.text}")

        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            
            if next_method != "GET" and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")
            elif next_url and next_method != "NONE":
                print(f"[{res.status_code} Intercepted] HATEOAS Auto-Navigating to: {next_method} {next_url}")
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                time.sleep(1)
                return self.execute_request(next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count)

        raise PaymentExecutionError(f"API Error {res.status_code}: {error_data.get('message', res.text)} | Next Action: {next_action}")

    def _handle_402_challenge(self, response, payload, headers, url, method, _current_hop, _payment_retry_count) -> dict:
        data = response.json()
        challenge = data.get("challenge", {})
        instruction = data.get("instruction_for_agents", {}) 
        
        scheme = challenge.get("scheme")
        amount = float(challenge.get("amount", 0))
        asset = challenge.get("asset", payload.get("asset", "SATS"))

        # --- Policy Enforcement ---
        self._enforce_policy(scheme, asset, amount)

        print(f"[402 Intercepted] Processing {amount} {asset} payment via {scheme}...")

        proof_ref = ""
        network_name = ""

        if scheme in ["x402", "x402-direct"]:
            if not self.evm_signer:
                raise PaymentExecutionError(f"{scheme} 決済には evm_signer が必要です。")

            treasury_address = challenge.get("parameters", {}).get("destination") or instruction.get("treasury_address")
            chain_id = challenge.get("parameters", {}).get("chain_id") or instruction.get("chain_id", 137)
            token_address = challenge.get("parameters", {}).get("token_address") or instruction.get("token_address")
            
            if not treasury_address: raise PaymentExecutionError("HATEOAS Error: Treasury address is missing.")
            
            if scheme == "x402":
                relayer_url = instruction.get("relayer_endpoint")
                if not relayer_url: raise PaymentExecutionError("HATEOAS Error: Relayer endpoint is missing.")
                proof_ref = self.evm_signer.execute_x402_gasless(
                    asset, amount, relayer_url, treasury_address, int(chain_id), token_address
                )
            else: # x402-direct
                if not self.evm_rpc_url: raise PaymentExecutionError("RPC URL is required for x402-direct payment.")
                proof_ref = self.evm_signer.execute_x402_direct(
                    asset, amount, treasury_address, int(chain_id), token_address, self.evm_rpc_url
                )
                
            network_name = "EVM"
            payload["paymentAuth"] = {"scheme": scheme, "proof": proof_ref}
            headers["Authorization"] = f"{scheme} {proof_ref}"

        elif scheme == "x402-solana":
            if not self.solana_signer:
                raise PaymentExecutionError("x402-solana 決済には solana_signer が必要です。")

            treasury_address = challenge.get("parameters", {}).get("payTo") or instruction.get("treasury_address")
            reference_key = challenge.get("parameters", {}).get("reference") or instruction.get("reference") 
            
            if not treasury_address: raise PaymentExecutionError("HATEOAS Error: 'payTo' missing.")

            proof_ref = self.solana_signer.execute_x402_solana(amount, treasury_address, reference_key)
            network_name = "Solana"
            payload["paymentAuth"] = {"scheme": scheme, "proof": proof_ref}
            headers["Authorization"] = f"x402-solana {proof_ref}"

        elif scheme in ["L402", "MPP", "Payment"]:
            if not self.ln_adapter:
                raise PaymentExecutionError(f"{scheme} 決済には ln_adapter が必要です。")

            auth_header = response.headers.get("WWW-Authenticate", "")
            def safe_extract(pattern, text, fallback):
                match = re.search(pattern, text)
                return match.group(1) if match else fallback

            invoice = challenge.get("parameters", {}).get("invoice") or safe_extract(r'invoice="([^"]+)"', auth_header, None)
            if not invoice: raise InvoiceParseError("Invoice not found in 402 challenge header.")

            proof_ref = self.ln_adapter.pay_invoice(invoice)
            network_name = "Lightning"
            
            if scheme == "L402":
                macaroon = safe_extract(r'macaroon="([^"]+)"', auth_header, None)
                if not macaroon: raise InvoiceParseError("Macaroon not found.")
                headers["Authorization"] = f"L402 {macaroon}:{proof_ref}"
            else:
                charge_id = challenge.get("parameters", {}).get("charge") or safe_extract(r'charge="([^"]+)"', auth_header, "unknown_charge")
                headers["Authorization"] = f"Payment {charge_id}:{proof_ref}"

        # --- SettlementReceipt の生成と格納 ---
        self.last_receipt = SettlementReceipt(
            scheme=scheme,
            network=network_name,
            asset=asset,
            settled_amount=amount,
            proof_reference=proof_ref,
            verification_status="verified" if network_name == "Lightning" else "self_reported"
        )

        return self.execute_request(method, url, payload, headers, _current_hop + 1, _payment_retry_count + 1)

    # ------------------------------------------
    # ⚡ 非同期 (Async) エンジン 
    # ------------------------------------------
    async def execute_request_async(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, _current_hop: int = 0, _payment_retry_count: int = 0) -> dict:
        url = endpoint_path if endpoint_path.startswith("http") else f"{self.base_url}{endpoint_path}"
        headers = dict(headers or {}) 

        if not any(k.lower() == "user-agent" for k in headers.keys()):
            headers["User-Agent"] = CUSTOM_USER_AGENT

        payload = payload or {}
        method_upper = method.upper()
        is_get = method_upper == "GET"
        req_kwargs = {
            "json": None if is_get else payload,
            "params": payload if is_get else None,
            "headers": headers
        }

        async with httpx.AsyncClient(follow_redirects=True) as client:
            res = await client.request(method_upper, url, **req_kwargs)

        if 200 <= res.status_code < 300:
            if not res.content: return {"status": "success", "message": "No content returned"}
            return res.json()

        if res.status_code == 402:
            if _payment_retry_count >= self.max_payment_retries: raise PaymentExecutionError("Max 402 retries exceeded")
            return await self._handle_402_challenge_async(res, payload, headers, url, method_upper, _current_hop, _payment_retry_count)

        try:
            error_data = res.json()
            error_obj = HateoasErrorResponse(**error_data)
            next_action = error_obj.next_action
        except Exception:
            raise PaymentExecutionError(f"HTTP {res.status_code}: {res.text}")

        if self.auto_navigate and next_action and _current_hop < self.max_hops:
            next_url = next_action.url
            next_method = (next_action.method or "GET").upper()
            
            if next_method != "GET" and not self.allow_unsafe_navigate:
                raise NavigationGuardrailError(f"[Guardrail] Stopped unsafe automatic navigation to {next_method} {next_url}")
            elif next_url and next_method != "NONE":
                print(f"[{res.status_code} Intercepted ASYNC] HATEOAS Auto-Navigating to: {next_method} {next_url}")
                merged_payload = {**payload, **(next_action.suggested_payload or {})}
                merged_headers = {**headers, **(next_action.suggested_headers or {})}
                await asyncio.sleep(1) 
                return await self.execute_request_async(next_method, next_url, merged_payload, merged_headers, _current_hop + 1, _payment_retry_count)

        raise PaymentExecutionError(f"API Error {res.status_code}: {error_data.get('message', res.text)} | Next Action: {next_action}")

    async def _handle_402_challenge_async(self, response, payload, headers, url, method, _current_hop, _payment_retry_count) -> dict:
        data = response.json()
        challenge = data.get("challenge", {})
        instruction = data.get("instruction_for_agents", {}) 
        
        scheme = challenge.get("scheme")
        amount = float(challenge.get("amount", 0))
        asset = challenge.get("asset", payload.get("asset", "SATS"))
        loop = asyncio.get_event_loop()

        # --- Policy Enforcement ---
        self._enforce_policy(scheme, asset, amount)

        print(f"[402 Intercepted ASYNC] Processing {amount} {asset} payment via {scheme}...")

        proof_ref = ""
        network_name = ""

        if scheme in ["x402", "x402-direct"]:
            if not self.evm_signer:
                raise PaymentExecutionError(f"{scheme} 決済には evm_signer が必要です。")

            treasury_address = challenge.get("parameters", {}).get("destination") or instruction.get("treasury_address")
            chain_id = challenge.get("parameters", {}).get("chain_id") or instruction.get("chain_id", 137)
            token_address = challenge.get("parameters", {}).get("token_address") or instruction.get("token_address")
            
            if not treasury_address: raise PaymentExecutionError("HATEOAS Error: Treasury address is missing.")

            if scheme == "x402":
                relayer_url = instruction.get("relayer_endpoint")
                if not relayer_url: raise PaymentExecutionError("HATEOAS Error: Relayer endpoint is missing.")
                proof_ref = await loop.run_in_executor(None, self.evm_signer.execute_x402_gasless, asset, amount, relayer_url, treasury_address, int(chain_id), token_address)
            else: # x402-direct
                if not self.evm_rpc_url: raise PaymentExecutionError("RPC URL is required for x402-direct payment.")
                proof_ref = await loop.run_in_executor(None, self.evm_signer.execute_x402_direct, asset, amount, treasury_address, int(chain_id), token_address, self.evm_rpc_url)

            network_name = "EVM"
            payload["paymentAuth"] = {"scheme": scheme, "proof": proof_ref}
            headers["Authorization"] = f"{scheme} {proof_ref}"

        elif scheme == "x402-solana":
            if not self.solana_signer:
                raise PaymentExecutionError("x402-solana 決済には solana_signer が必要です。")

            treasury_address = challenge.get("parameters", {}).get("payTo") or instruction.get("treasury_address")
            reference_key = challenge.get("parameters", {}).get("reference") or instruction.get("reference") 
            
            if not treasury_address: raise PaymentExecutionError("HATEOAS Error: 'payTo' missing.")

            proof_ref = await loop.run_in_executor(None, self.solana_signer.execute_x402_solana, amount, treasury_address, reference_key)
            network_name = "Solana"
            payload["paymentAuth"] = {"scheme": scheme, "proof": proof_ref}
            headers["Authorization"] = f"x402-solana {proof_ref}"

        elif scheme in ["L402", "MPP", "Payment"]:
            if not self.ln_adapter:
                raise PaymentExecutionError(f"{scheme} 決済には ln_adapter が必要です。")

            auth_header = response.headers.get("WWW-Authenticate", "")
            def safe_extract(pattern, text, fallback):
                match = re.search(pattern, text)
                return match.group(1) if match else fallback

            invoice = challenge.get("parameters", {}).get("invoice") or safe_extract(r'invoice="([^"]+)"', auth_header, None)
            if not invoice: raise InvoiceParseError("Invoice not found in 402 challenge.")

            proof_ref = await loop.run_in_executor(None, self.ln_adapter.pay_invoice, invoice)
            network_name = "Lightning"
            
            if scheme == "L402":
                macaroon = safe_extract(r'macaroon="([^"]+)"', auth_header, None)
                if not macaroon: raise InvoiceParseError("Macaroon not found.")
                headers["Authorization"] = f"L402 {macaroon}:{proof_ref}"
            else:
                charge_id = challenge.get("parameters", {}).get("charge") or safe_extract(r'charge="([^"]+)"', auth_header, "unknown_charge")
                headers["Authorization"] = f"Payment {charge_id}:{proof_ref}"

        # --- SettlementReceipt の生成と格納 ---
        self.last_receipt = SettlementReceipt(
            scheme=scheme,
            network=network_name,
            asset=asset,
            settled_amount=amount,
            proof_reference=proof_ref,
            verification_status="verified" if network_name == "Lightning" else "self_reported"
        )

        return await self.execute_request_async(method, url, payload, headers, _current_hop + 1, _payment_retry_count + 1)

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
        # --- v1.2.0 Boundary Cleanup Additions ---
        evm_signer: Optional[EVMSigner] = None,
        ln_adapter: Optional[LightningProvider] = None,
        solana_signer: Optional[SolanaSigner] = None,
        policy: Optional[PaymentPolicy] = None,
    ):
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
            policy=policy
        )

        if private_key and not agent_id:
            try:
                self.agent_id = Account.from_key(private_key).address
            except Exception:
                try:
                    from solders.keypair import Keypair
                    self.agent_id = str(Keypair.from_base58_string(private_key).pubkey())
                except Exception:
                    self.agent_id = "Anonymous_Agent"
        else:
            self.agent_id = agent_id or "Anonymous_Agent"
            
        self.probe_token = None
        self.faucet_token = None

    def _inject_telemetry(self, headers: Optional[dict]) -> dict:
        headers = dict(headers or {})
        headers["X-LN-Church-Agent-Version"] = SDK_VERSION
        if not any(k.lower() == "x-ln-church-request-id" for k in headers.keys()):
            headers["X-LN-Church-Request-Id"] = str(uuid.uuid4())
        return headers

    def execute_request(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, _current_hop: int = 0, _payment_retry_count: int = 0) -> dict:
        telemetry_headers = self._inject_telemetry(headers)
        return super().execute_request(method, endpoint_path, payload, telemetry_headers, _current_hop, _payment_retry_count)

    async def execute_request_async(self, method: str, endpoint_path: str, payload: Optional[dict] = None, headers: Optional[dict] = None, _current_hop: int = 0, _payment_retry_count: int = 0) -> dict:
        telemetry_headers = self._inject_telemetry(headers)
        return await super().execute_request_async(method, endpoint_path, payload, telemetry_headers, _current_hop, _payment_retry_count)

    # ------------------------------------------
    # 同期 (Sync) メソッド群
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

    def draw_omikuji(self, asset: AssetType = AssetType.USDC, scheme: Optional[str] = None) -> OmikujiResponse:
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        return OmikujiResponse(**self.execute_request("POST", "/api/agent/omikuji", payload, headers))

    def submit_confession(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None) -> ConfessionResponse:
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        return ConfessionResponse(**self.execute_request("POST", "/api/agent/confession", payload))

    def offer_hono(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> HonoResponse:
        target_scheme = scheme or ("MPP" if asset == AssetType.SATS else "x402-direct")
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
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"scheme": target_scheme, "asset": asset.value}
        return CompareResponse(**self.execute_request("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload))

    def request_fast_pass_aggregate(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> AggregateResponse:
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
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
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        res = self.execute_request("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)

    # ------------------------------------------
    # ⚡ 非同期 (Async) メソッド群
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

    async def draw_omikuji_async(self, asset: AssetType = AssetType.USDC, scheme: Optional[str] = None) -> OmikujiResponse:
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"agentId": self.agent_id, "clientType": "AI", "scheme": target_scheme, "asset": asset.value}
        if self.faucet_token:
            payload["paymentOverride"] = {"type": "faucet", "proof": self.faucet_token, "asset": "FAUCET_CREDIT"}
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}
        res = await self.execute_request_async("POST", "/api/agent/omikuji", payload, headers)
        return OmikujiResponse(**res)

    async def submit_confession_async(self, raw_message: str, asset: AssetType = AssetType.SATS, context: dict = None, scheme: Optional[str] = None) -> ConfessionResponse:
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"agentId": self.agent_id, "raw_message": raw_message, "context": context or {}, "scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", "/api/agent/confession", payload)
        return ConfessionResponse(**res)

    async def offer_hono_async(self, amount: float, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> HonoResponse:
        target_scheme = scheme or ("MPP" if asset == AssetType.SATS else "x402-direct")
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
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"scheme": target_scheme, "asset": asset.value}
        res = await self.execute_request_async("POST", f"/api/agent/benchmark/trials/{trial_id}/agent/{self.agent_id}/compare", payload)
        return CompareResponse(**res)

    async def request_fast_pass_aggregate_async(self, asset: AssetType = AssetType.SATS, scheme: Optional[str] = None) -> AggregateResponse:
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
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
        target_scheme = scheme or ("L402" if asset == AssetType.SATS else "x402")
        payload = {"scheme": target_scheme, "asset": asset.value, "agentId": self.agent_id}
        res = await self.execute_request_async("GET", f"/api/agent/monzen/graph", payload=payload)
        return MonzenGraphResponse(**res)