import base58
import time
from typing import Optional, Dict, Any

# 内部モジュールとモデルのインポート
from .protocols import SolanaSigner
from ..models import ParsedChallenge

# --- Solana / SPL Token 定数 ---
try:
    from solders.pubkey import Pubkey
    from solders.keypair import Keypair
    # Solana Mainnet USDC Mint Address
    USDC_MINT = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
except ImportError:
    Pubkey = Keypair = Any
    USDC_MINT = TOKEN_PROGRAM_ID = ASSOCIATED_TOKEN_PROGRAM_ID = None

# ==========================================
# 1. 標準 x402 規格用の証明生成
# ==========================================
def sign_standard_x402_solana(private_key: str, challenge: ParsedChallenge) -> str:
    """
    x402 Foundation 標準に準拠した Solana 証明文字列を生成。
    形式: <macaroon_base64>:<signature_base58>
    """
    macaroon = challenge.parameters.get("macaroon") or challenge.parameters.get("token") or ""
    # 決済の証拠（Solana のトランザクション署名）を取得
    signature = challenge.parameters.get("signature") or challenge.parameters.get("txHash", "")
    
    return f"{macaroon}:{signature}"

# ==========================================
# 2. Concrete Adapter (LocalSolanaAdapter)
# ==========================================
class LocalSolanaAdapter(SolanaSigner):
    """Solana 秘密鍵を保持し、送金を実行するアダプター"""
    
    def __init__(self, private_key: str):
        if not private_key:
            raise ValueError("LocalSolanaAdapter requires a private_key.")
        try:
            from solders.keypair import Keypair
            self.keypair = Keypair.from_base58_string(private_key)
        except ImportError:
            raise ImportError(
                "Solana support requires 'solana' and 'solders'. "
                "Install with: pip install ln-church-agent[solana]"
            )

    @property
    def address(self) -> str:
        return str(self.keypair.pubkey())

    def execute_lnc_solana_transfer_settlement(
        self, asset: str, human_amount: float, treasury_address: str, 
        reference: str, rpc_url: str = None
    ) -> str:
        """
        [LN教独自] Solana SPL Token (USDC) 送金による奉納。
        HATEOASで指定された reference 公開鍵をTXに含めます 。
        """
        from solana.rpc.api import Client
        from solana.transaction import Transaction
        from solders.instruction import Instruction, AccountMeta
        from solders.system_program import ID as SYS_PROGRAM_ID
        import spl.token.instructions as spl_token

        node_url = rpc_url or "https://api.mainnet-beta.solana.com"
        client = Client(node_url)
        
        sender_pubkey = self.keypair.pubkey()
        dest_pubkey = Pubkey.from_string(treasury_address)
        
        # 1. ATA (Associated Token Accounts) の解決
        def get_ata(owner: Pubkey):
            from spl.token.instructions import get_associated_token_address
            return get_associated_token_address(owner, USDC_MINT)

        sender_ata = get_ata(sender_pubkey)
        dest_ata = get_ata(dest_pubkey)

        # 2. 金額の計算 (USDCは6桁)
        amount_raw = int(human_amount * 1_000_000)

        # 3. 送金命令の作成
        transfer_ix = spl_token.transfer_checked(
            spl_token.TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=USDC_MINT,
                dest=dest_ata,
                owner=sender_pubkey,
                amount=amount_raw,
                decimals=6
            )
        )

        # 4. トランザクション構築
        recent_blockhash = client.get_latest_blockhash().value.blockhash
        tx = Transaction(recent_blockhash=recent_blockhash, fee_payer=sender_pubkey)
        tx.add(transfer_ix)

        # 5. [重要] reference キーの追加 (LN教特有の照合用) 
        if reference:
            ref_pubkey = Pubkey.from_string(reference)
            tx.instructions[0].accounts.append(
                AccountMeta(pubkey=ref_pubkey, is_signer=False, is_writable=False)
            )

        # 6. 署名と送信
        tx.sign(self.keypair)
        res = client.send_raw_transaction(tx.serialize())
        
        if not res.value:
            raise Exception(f"Solana Transaction Failed: {res}")

        # SignatureをBase58で返す
        return str(res.value)

# ==========================================
# 3. 後方互換性のためのグローバル関数 (Alias)
# ==========================================
def execute_x402_solana(private_key: str, challenge: ParsedChallenge) -> str:
    """旧バージョンの関数名。内部で LocalSolanaAdapter を使用して互換性を維持 [cite: 985]。"""
    adapter = LocalSolanaAdapter(private_key)
    
    # challenge から必要な値を抽出
    asset = challenge.asset
    amount = challenge.amount
    # ChallengeのJSONボディ (parameters) から取得
    params = challenge.parameters
    treasury = params.get("payTo") or params.get("destination")
    reference = params.get("reference")
    
    return adapter.execute_lnc_solana_transfer_settlement(
        asset, amount, treasury, reference
    )