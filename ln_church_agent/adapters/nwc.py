import requests
from urllib.parse import urlparse, parse_qs
from ..crypto.protocols import LightningProvider

class NWCAdapter(LightningProvider):
    """
    Nostr Wallet Connect (NIP-47) Adapter via HTTP Bridge.
    エージェントは秘密鍵を持たず、NWC URIを通じてリモートウォレットに署名を委譲します。
    ※ v1.2.0 Experimental: 現在はHTTP Bridge Gatewayを経由した通信のみをサポートします。
    """
    def __init__(self, nwc_uri: str, bridge_url: str):
        if not nwc_uri.startswith("nostr+walletconnect://"):
            raise ValueError("Invalid NWC URI format.")
        if not bridge_url:
            raise ValueError("NWCAdapter in v1.2.0 requires an HTTP `bridge_url`.")
            
        self.nwc_uri = nwc_uri
        self.bridge_url = bridge_url
        
        parsed = urlparse(nwc_uri)
        self.wallet_pubkey = parsed.netloc
        self.relay = parse_qs(parsed.query).get('relay', [''])[0]

    def pay_invoice(self, invoice: str) -> str:
        # NWC HTTP Bridgeの標準化ペイロード
        payload = {
            "method": "pay_invoice",
            "params": {"invoice": invoice},
            "nwc_uri": self.nwc_uri
        }
        
        try:
            res = requests.post(self.bridge_url, json=payload, timeout=30)
            res.raise_for_status()
            data = res.json()
            
            preimage = data.get("preimage") or data.get("result", {}).get("preimage")
            if not preimage:
                raise Exception("Payment succeeded but gateway did not return a preimage.")
            return preimage
            
        except Exception as e:
            raise Exception(f"NWC Bridge Payment Failed: {str(e)}")

    def get_balance(self) -> float:
        # v1.2.0時点ではモック（今後の拡張用）
        return 0.0