# protocols.py
from typing import Protocol, Optional, Dict, Any, Union
from ..models import ParsedChallenge, L402ExecutionReport

class EVMSigner(Protocol):
    """EVMにおけるx402決済を抽象化するインターフェース"""
    @property
    def address(self) -> str: ...

    def execute_lnc_evm_relay_settlement(
        self, asset: str, human_amount: float, relayer_url: str, treasury_address: str, 
        chain_id: int = 137, token_address: Optional[str] = None
    ) -> str: ...
    
    def execute_lnc_evm_transfer_settlement(
        self, asset: str, human_amount: float, treasury_address: str, 
        chain_id: int = 137, token_address: Optional[str] = None, rpc_url: Optional[str] = None
    ) -> str: ...

class LightningProvider(Protocol):
    """Lightning Networkの決済を担う抽象インターフェース"""
    def pay_invoice(self, invoice: str) -> str: ...

class SolanaSigner(Protocol):
    """Solanaにおけるx402決済を抽象化するインターフェース"""
    @property
    def address(self) -> str: ...

    def execute_lnc_solana_transfer_settlement(
        self, asset: str, human_amount: float, treasury_address: str, 
        reference: str, rpc_url: Optional[str] = None
    ) -> str: ...

class L402Executor(Protocol):
    """L402決済実行を委譲するためのインターフェース"""
    def execute_l402(
        self, url: str, method: str, parsed: ParsedChallenge, headers: Dict[str, str], payload: Dict[str, Any]
    ) -> L402ExecutionReport: ...

class X402SvmSigner(Protocol):
    """Solana SVM における x402 exact 決済を抽象化するインターフェース"""
    @property
    def address(self) -> str: ...

    def generate_svm_exact_payload(
        self, network: str, asset: str, amount: Union[str, int, float], pay_to: str, 
        fee_payer: str, memo: Optional[str] = None
    ) -> Dict[str, Any]: ...