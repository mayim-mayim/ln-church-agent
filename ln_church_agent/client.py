import requests
import re
from typing import Optional
from eth_account import Account
from .models import AssetType, OmikujiResponse, AgentIdentity
from .crypto.evm import execute_x402_gasless_payment
from .crypto.lightning import pay_lightning_invoice

class LnChurchClient:
    def __init__(
        self, 
        agent_id: Optional[str] = None, 
        private_key: Optional[str] = None, 
        lnbits_url: Optional[str] = None,
        lnbits_key: Optional[str] = None,
        base_url: str = "https://kari.mayim-mayim.com/api/agent" # 引数に追加し、デフォルト値を設定
    ):
        self.private_key = private_key
        if private_key and not agent_id:
            self.agent_id = Account.from_key(private_key).address
        else:
            self.agent_id = agent_id or "Anonymous_Agent"
            
        self.lnbits_url = lnbits_url
        self.lnbits_key = lnbits_key
        self.base_url = base_url.rstrip('/') # 末尾のスラッシュを削除して正規化
        self.probe_token = None
        self.faucet_token = None

    def init_probe(self):
        """Phase 0: システムの初期化と能力証明"""
        res1 = requests.get(f"{self.base_url}/probe", params={"agentId": self.agent_id, "src": "sdk"})
        if not res1.ok: raise Exception(f"Probe failed: {res1.text}")
        
        token = res1.json().get("probe_token")
        
        # HATEOASに従ってStage 2を実行
        res2 = requests.get(f"{self.base_url}/probe/next", params={"agentId": self.agent_id, "token": token})
        if res2.ok:
            self.probe_token = token
            print("[System] Probe Completed. Autonomous capabilities verified.")

    def claim_faucet_if_empty(self):
        """資金ゼロの場合にFaucetから初期グラントを取得"""
        res = requests.post(f"{self.base_url}/faucet", json={"agentId": self.agent_id})
        if res.ok:
            self.faucet_token = res.json().get("grant_token")
            print("[System] Faucet Claimed. Payment bypass unlocked.")

    def draw_omikuji(self, asset: AssetType = AssetType.USDC) -> OmikujiResponse:
        """御神籤を引く（402決済を自動ハンドリング）"""
        scheme = "L402" if asset == AssetType.SATS else "x402"
        if self.faucet_token:
            scheme = "faucet"
            asset = AssetType.FAUCET_CREDIT

        payload = {
            "agentId": self.agent_id,
            "clientType": "AI",
            "scheme": scheme,
            "asset": asset.value
        }
        
        if self.faucet_token:
            payload["paymentAuth"] = {"scheme": "faucet", "proof": self.faucet_token}

        headers = {"x-probe-token": self.probe_token} if self.probe_token else {}

        # 1. 初回リクエスト
        res = requests.post(f"{self.base_url}/omikuji", json=payload, headers=headers)

        # 2. 402 Payment Required のインターセプト
        if res.status_code == 402:
            return self._handle_402_challenge(res, payload, headers)
            
        elif res.status_code == 200:
            return OmikujiResponse(**res.json())
        else:
            raise Exception(f"API Error: {res.text}")

    def _handle_402_challenge(self, response, payload, headers) -> OmikujiResponse:
        data = response.json()
        challenge = data.get("challenge", {})
        scheme = challenge.get("scheme")
        amount = float(challenge.get("amount", 0))

        print(f"[402 Intercepted] Processing {amount} {challenge.get('asset')} payment via {scheme}...")

        if scheme == "x402":
            tx_hash = execute_x402_gasless_payment(self.private_key, payload["asset"], amount)
            payload["paymentAuth"] = {"scheme": "x402", "proof": tx_hash}
            
        elif scheme == "L402":
            auth_header = response.headers.get("WWW-Authenticate", "")
            invoice = challenge["parameters"]["invoice"]
            
            # Macaroon抽出
            macaroon_match = re.search(r'macaroon="([^"]+)"', auth_header)
            if not macaroon_match: raise Exception("Macaroon not found in challenge")
            macaroon = macaroon_match.group(1)
            
            preimage = pay_lightning_invoice(invoice, self.lnbits_url, self.lnbits_key)
            headers["Authorization"] = f"L402 {macaroon}:{preimage}"

        # 3. 決済証明付きで再リクエスト
        final_res = requests.post(f"{self.base_url}/omikuji", json=payload, headers=headers)
        
        if final_res.status_code == 200:
            # 成功したらついでにIdentityも更新しておく（おまけ機能）
            self.issue_identity()
            return OmikujiResponse(**final_res.json())
        else:
            raise Exception(f"Settlement failed: {final_res.text}")

    def issue_identity(self) -> AgentIdentity:
        """パスポート（写身証）の発行"""
        res = requests.post(f"{self.base_url}/identity/issue", json={"agentId": self.agent_id})
        return AgentIdentity(**res.json()) if res.ok else None