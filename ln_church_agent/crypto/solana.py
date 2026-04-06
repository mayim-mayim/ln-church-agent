import os
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from spl.token.instructions import transfer_checked, TransferCheckedParams, get_associated_token_address
from solders.transaction import VersionedTransaction
from solders.message import MessageV0

# --- 定数設定 ---
# Solana Mainnet USDC Mint Address
USDC_MINT = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
# デフォルトRPC（環境変数 SOLANA_RPC_URL で上書き可能）
DEFAULT_RPC = "https://api.mainnet-beta.solana.com"

def execute_x402_solana_payment(private_key_base58: str, amount: float, destination_addr: str) -> str:
    """
    Solanaネットワーク上でUSDCのSPLトークン転送を完遂し、Signatureを返す。
    """
    if not private_key_base58:
        raise ValueError("x402-solana決済には private_key (Base58) が必要です。")

    rpc_url = os.environ.get("SOLANA_RPC_URL", DEFAULT_RPC)
    client = Client(rpc_url)

    # 1. 鍵ペアと宛先の復元
    try:
        payer = Keypair.from_base58_string(private_key_base58)
        dest_pubkey = Pubkey.from_string(destination_addr)
    except Exception as e:
        raise ValueError(f"Invalid Solana credentials or destination: {e}")

    # 2. 金額の変換 (USDCは小数点6桁)
    amount_units = int(amount * 1_000_000)

    # 3. ATA (Associated Token Account) の導出
    source_ata = get_associated_token_address(payer.pubkey(), USDC_MINT)
    dest_ata = get_associated_token_address(dest_pubkey, USDC_MINT)

    # 4. 命令（Instruction）の構築
    transfer_ix = transfer_checked(
        TransferCheckedParams(
            program_id=TOKEN_PROGRAM_ID,
            source=source_ata,
            mint=USDC_MINT,
            dest=dest_ata,
            owner=payer.pubkey(),
            amount=amount_units,
            decimals=6
        )
    )

    # 5. トランザクションの構築と署名
    recent_blockhash_resp = client.get_latest_blockhash()
    if not recent_blockhash_resp.value:
        raise Exception("Failed to fetch recent blockhash from Solana RPC.")
    recent_blockhash = recent_blockhash_resp.value.blockhash

    msg = MessageV0.try_compile(
        payer.pubkey(), 
        [transfer_ix], 
        [], # Address Lookup Tables (今回は不要)
        recent_blockhash
    )
    tx = VersionedTransaction(msg, [payer])

    # 6. 送信と結果の取得
    res = client.send_transaction(tx)
    if not res.value:
        raise Exception("Solana transaction failed to send.")

    return str(res.value) # Base58形式のSignature (txHashに相当)