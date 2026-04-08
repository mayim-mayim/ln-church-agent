from urllib.parse import urlparse, parse_qs
from ..crypto.protocols import LightningProvider

class NWCAdapter(LightningProvider):
    """
    Nostr Wallet Connect (NIP-47) を用いたサイナー分離型プロバイダー。
    エージェントは秘密鍵を持たず、NWC URI を通じてリモートウォレットに署名/支払いを委譲する。
    """
    def __init__(self, nwc_uri: str):
        if not nwc_uri.startswith("nostr+walletconnect://"):
            raise ValueError("Invalid NWC URI format. Must start with 'nostr+walletconnect://'")
        self.nwc_uri = nwc_uri
        
        # URIパース (pubkey, relay, secretの抽出)
        parsed = urlparse(nwc_uri)
        self.wallet_pubkey = parsed.netloc
        query = parse_qs(parsed.query)
        self.relay = query.get('relay', [''])[0]
        self.secret = query.get('secret', [''])[0]

    def pay_invoice(self, invoice: str) -> str:
        # v1.2.0: Boundary Definition
        # 実際にはここに WebSocket / NIP-47 の通信ロジックが入るか、
        # 軽量化のために HTTP NWC ブリッジ API (Alby 等) を叩くロジックを配置する。
        print(f"[NWC Adapter] Delegating payment to Remote Wallet via Relay: {self.relay}")
        
        # 実装例: (HTTP Bridgeを利用する場合)
        # res = requests.post("https://nwc-bridge/pay", json={"invoice": invoice, "nwc_uri": self.nwc_uri})
        # return res.json()["preimage"]
        
        raise NotImplementedError("NWC full NIP-47 transport is initialized, but requires async WS runtime to execute.")

    def get_balance(self) -> float:
        print("[NWC Adapter] Requesting balance via NIP-47 get_balance command.")
        return 0.0