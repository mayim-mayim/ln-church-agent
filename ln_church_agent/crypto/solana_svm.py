import base64
from typing import Optional, Dict, Any, Union
from .protocols import X402SvmSigner

SOLANA_MAINNET_CAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_DEVNET_CAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

KNOWN_SPL_TOKEN_DECIMALS = {
    # Solana Mainnet USDC
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": 6,
    # Solana Devnet USDC
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU": 6,
}

MEMO_PROGRAM_ID_STR = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

class LocalSvmAdapter(X402SvmSigner):
    """
    SVM Exact 用のローカル・トランザクション構築アダプタ。
    x402 v2 規格に準拠した partially-signed VersionedTransaction を生成します。
    """
    def __init__(self, private_key: str, rpc_url: Optional[str] = None):
        if not private_key:
            raise ValueError("LocalSvmAdapter requires a private_key.")
        
        self.private_key = private_key
        self.rpc_url = rpc_url  # v1.7.0 Final: ここでは保持のみ。解決は生成時に行う。
        try:
            from solders.keypair import Keypair
            self.keypair = Keypair.from_base58_string(private_key)
        except ImportError:
            raise ImportError(
                "SVM support dependencies are missing. "
                "Install with: pip install 'ln-church-agent[svm]'"
            )
        except Exception as e:
            raise ValueError(f"Invalid Solana Base58 private key for SVM Adapter: {e}")

    @property
    def address(self) -> str:
        return str(self.keypair.pubkey())

    def generate_svm_exact_payload(
        self, network: str, asset: str, amount: Union[str, int, float], pay_to: str,
        fee_payer: str, memo: Optional[str] = None
    ) -> Dict[str, Any]:
        
        # 👇 修正: バリデーションを "先" に実行する
        if not network.startswith("solana:"):
            raise ValueError(f"Invalid CAIP-2 network identifier for SVM exact: {network}")
        
        if network in ["solana:mainnet", "solana:devnet"]:
            raise ValueError(f"Unsupported Solana network format '{network}'. Use CAIP-2 genesisHash (e.g., '{SOLANA_MAINNET_CAIP2}').")

        if asset not in KNOWN_SPL_TOKEN_DECIMALS:
            raise ValueError(f"Unsupported SPL token mint for SVM exact: {asset}. Token decimals are required.")
        
        # 👇 修正: その "後" に RPCエンドポイントを解決する
        target_rpc = self.rpc_url
        if not target_rpc:
            if network == SOLANA_MAINNET_CAIP2:
                target_rpc = "https://api.mainnet-beta.solana.com"
            elif network == SOLANA_DEVNET_CAIP2:
                target_rpc = "https://api.devnet.solana.com"
            else:
                raise ValueError(f"RPC URL must be specified for unknown network: {network}")

        decimals = KNOWN_SPL_TOKEN_DECIMALS[asset]
        raw_amount = int(amount)  # Wire-level minimal unit

        try:
            from solders.pubkey import Pubkey
            from solders.instruction import Instruction
            from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
            from solders.message import MessageV0
            from solders.transaction import VersionedTransaction
            from solders.null_signer import NullSigner
            from solana.rpc.api import Client
            from spl.token.instructions import transfer_checked, TransferCheckedParams, get_associated_token_address
            from spl.token.constants import TOKEN_PROGRAM_ID

            payer_pubkey = self.keypair.pubkey()
            dest_pubkey = Pubkey.from_string(pay_to)
            mint_pubkey = Pubkey.from_string(asset)
            fee_payer_pubkey = Pubkey.from_string(fee_payer)

            # ATA (Associated Token Account) の解決
            source_ata = get_associated_token_address(payer_pubkey, mint_pubkey)
            dest_ata = get_associated_token_address(dest_pubkey, mint_pubkey)

            # RPCから最新のBlockhashを取得
            client = Client(target_rpc)
            blockhash_resp = client.get_latest_blockhash()
            recent_blockhash = blockhash_resp.value.blockhash

            instructions = []
            
            # 1. Compute Budget Instructions
            instructions.append(set_compute_unit_limit(200_000))
            instructions.append(set_compute_unit_price(1))

            # 2. Memo Instruction (Optional)
            if memo:
                memo_ix = Instruction(
                    program_id=Pubkey.from_string(MEMO_PROGRAM_ID_STR),
                    accounts=[],
                    data=memo.encode('utf-8')
                )
                instructions.append(memo_ix)

            # 3. SPL Token TransferChecked Instruction
            instructions.append(
                transfer_checked(
                    TransferCheckedParams(
                        program_id=TOKEN_PROGRAM_ID,
                        source=source_ata,
                        mint=mint_pubkey,
                        dest=dest_ata,
                        owner=payer_pubkey,
                        amount=raw_amount,
                        decimals=decimals,
                        signers=[]
                    )
                )
            )

            if not instructions:
                raise RuntimeError("SVM exact transaction has no instructions.")

            # Facilitator(fee_payer) を Payer として MessageV0 をコンパイル
            msg = MessageV0.try_compile(
                payer=fee_payer_pubkey,
                instructions=instructions,
                address_lookup_table_accounts=[],
                recent_blockhash=recent_blockhash
            )

            # 署名者の順序を Message の AccountKeys と一致させる (Partial Sign)
            # Payer(fee_payer) は NullSigner(ダミー署名) とし、Sender は本物の Keypair で署名する
            num_signers = msg.header.num_required_signatures
            signers = []
            for key in msg.account_keys[:num_signers]:
                if key == payer_pubkey:
                    signers.append(self.keypair)
                else:
                    signers.append(NullSigner(key))

            tx = VersionedTransaction(msg, signers)

            # Serialize & Base64 Encode
            tx_bytes = bytes(tx)
            tx_b64 = base64.b64encode(tx_bytes).decode('utf-8')

            return {"transaction": tx_b64}

        except ImportError:
            raise ImportError("Solana dependencies are missing. Install with 'pip install ln-church-agent[svm]'")
        except Exception as e:
            # 秘密鍵をログに出さないように安全にエラーをバブリング
            raise RuntimeError(f"Local SVM transaction build failed: {str(e)}")