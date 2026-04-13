# protocols.py
from typing import Protocol, Optional

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