import requests
import re
from typing import Optional
from eth_account import Account
from .models import AssetType, OmikujiResponse, AgentIdentity
from .crypto.evm import execute_x402_gasless_payment
from .crypto.lightning import pay_lightning_invoice

# ==========================================
# 🌟 CORE: 汎用的な402決済処理クラス
# ==========================================
class Payment402Client:
    def __init__(
        self, 
        private_key: Optional[str] = None, 
        ln_api_url: Optional[str] = None,
        ln_api_key: Optional[str] = None,
        ln_provider: str = "lnbits",
        base_url: str = ""
    ):
        self.private_key = private_key
        self.ln_api_url = ln_api_url
        self.ln_api_key = ln_api_key
        self.ln_provider = ln_provider
        self.base_url = base_url.rstrip('/') if base_url else ""

    def execute_paid_action(self, endpoint_path: str, payload: dict, headers: Optional[dict] = None) -> dict:
        """Generic HTTP 402 Client: 任意のエンドポイントに対して決済を伴うPOSTリクエストを実行します。"""
        url = f"{self.base_url}{endpoint_path}" if self.base_url else endpoint_path
        headers = headers or {}

        # 1. 初回リクエスト
        res = requests.post(url, json=payload, headers=headers)

        # 2. 402 Payment Required のインターセプト
        if res.status_code == 402:
            return self._handle_402_challenge(res, payload, headers, url)
            
        elif res.status_code == 200:
            return res.json()
        else:
            raise Exception(f"API Error: {res.text}")

    def _handle_402_challenge(self, response, payload, headers, url) -> dict:
        data = response.json()
        challenge = data.get("challenge", {})
        scheme = challenge.get("scheme")
        amount = float(challenge.get("amount", 0))

        print(f"[402 Intercepted] Processing {amount} {challenge.get('asset')} payment via {scheme}...")

        # ==========================================
        # 1. Polygon Gasless (x402)
        # ==========================================
        if scheme == "x402":
            tx_hash = execute_x402_gasless_payment(self.private_key, payload.get("asset", "USDC"), amount)
            payload["paymentAuth"] = {"scheme": "x402", "proof": tx_hash}
            
        # ==========================================
        # 2. Lightning Network (L402)
        # ==========================================
        elif scheme == "L402":
            auth_header = response.headers.get("WWW-Authenticate", "")
            invoice = challenge.get("parameters", {}).get("invoice")
            
            macaroon_match = re.search(r'macaroon="([^"]+)"', auth_header)
            if not macaroon_match: raise Exception("Macaroon not found in challenge")
            macaroon = macaroon_match.group(1)
            
            preimage = pay_lightning_invoice(invoice, self.ln_api_url, self.ln_api_key, self.ln_provider)
            headers["Authorization"] = f"L402 {macaroon}:{preimage}"

        # ==========================================
        # 3. Machine Payments Protocol (MPP / Stripe)
        # ==========================================
        elif scheme == "Payment" or scheme == "MPP":
            auth_header = response.headers.get("WWW-Authenticate", "")
            
            # インボイスの抽出 (JSONまたはヘッダーから)
            invoice = challenge.get("parameters", {}).get("invoice")
            if not invoice:
                invoice_match = re.search(r'invoice="([^"]+)"', auth_header)
                if not invoice_match: raise Exception("Invoice not found in MPP challenge")
                invoice = invoice_match.group(1)
                
            # Stripe/Tempo特有の Charge Intent ID を抽出
            charge_id = challenge.get("parameters", {}).get("charge")
            if not charge_id:
                charge_match = re.search(r'charge="([^"]+)"', auth_header)
                charge_id = charge_match.group(1) if charge_match else "unknown_charge"

            print(f"[MPP] Initiating Machine Payments Protocol for Charge: {charge_id}")
            
            # 既存のLightning抽象化モジュールをそのまま再利用！
            preimage = pay_lightning_invoice(invoice, self.ln_api_url, self.ln_api_key, self.ln_provider)
            
            # MPP規格のAuthorizationヘッダーを構築 (ChargeID : Preimage)
            headers["Authorization"] = f"Payment {charge_id}:{preimage}"

        # ==========================================
        # 決済証明付きで再リクエスト
        # ==========================================
        final_res = requests.post(url, json=payload, headers=headers)
        
        if final_res.status_code == 200:
            return final_res.json()
        else:
            raise Exception(f"Settlement failed: {final_res.text}")

# ==========================================
# ⛩️ ADAPTER: LN Church 専用拡張クラス (Coreを継承)
# ==========================================
class LnChurchClient(Payment402Client):
    def __init__(
        self, 
        agent_id: Optional[str] = None, 
        private_key: Optional[str] = None, 
        ln_api_url: Optional[str] = None,
        ln_api_key: Optional[str] = None,
        ln_provider: str = "lnbits",
        base_url: str = "https://kari.mayim-mayim.com/api/agent" 
    ):
        # 親クラス(Core)の初期化を呼び出す
        super().__init__(private_key, ln_api_url, ln_api_key, ln_provider, base_url)

        if private_key and not agent_id:
            self.agent_id = Account.from_key(private_key).address
        else:
            self.agent_id = agent_id or "Anonymous_Agent"
            
        self.probe_token = None
        self.faucet_token = None

    def init_probe(self):
        res1 = requests.get(f"{self.base_url}/probe", params={"agentId": self.agent_id, "src": "sdk"})
        if not res1.ok: raise Exception(f"Probe failed: {res1.text}")
        token = res1.json().get("probe_token")
        
        res2 = requests.get(f"{self.base_url}/probe/next", params={"agentId": self.agent_id, "token": token})
        if res2.ok:
            self.probe_token = token
            print("[System] Probe Completed.")

    def claim_faucet_if_empty(self):
        res = requests.post(f"{self.base_url}/faucet", json={"agentId": self.agent_id})
        if res.ok:
            self.faucet_token = res.json().get("grant_token")
            print("[System] Faucet Claimed.")

    def draw_omikuji(self, asset: AssetType = AssetType.USDC) -> OmikujiResponse:
        scheme = "L402" if asset == AssetType.SATS else "x402"
        if self.faucet_token:
            scheme = "faucet"

        payload = {
            "agentId": self.agent_id,
            "clientType": "AI",
            "scheme": scheme,
            "asset": asset.value if hasattr(asset, 'value') else asset
        }
        
        if self.faucet_token:
            payload["paymentAuth"] = {"scheme": "faucet", "proof": self.faucet_token}

        # アダプター専用のヘッダー（probe_token）を注入
        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}

        # 🌟 親クラスの抽象化されたコアメソッドを利用！
        raw_response = self.execute_paid_action("/omikuji", payload, headers)
        
        self.issue_identity()
        return OmikujiResponse(**raw_response)

    def issue_identity(self) -> Optional[AgentIdentity]:
        res = requests.post(f"{self.base_url}/identity/issue", json={"agentId": self.agent_id})
        return AgentIdentity(**res.json()) if res.ok else None