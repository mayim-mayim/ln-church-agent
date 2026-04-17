# ln_church_agent/adapters/l402_delegate.py

from typing import Dict, Any
from ..crypto.protocols import L402Executor, LightningProvider
from ..models import ParsedChallenge, L402ExecutionReport
from ..exceptions import PaymentExecutionError

class NativeL402Executor(L402Executor):
    """ln-church-agent 標準の L402 実行器 (既存互換)"""
    def __init__(self, ln_adapter: LightningProvider):
        self.ln_adapter = ln_adapter

    def execute_l402(
        self, url: str, method: str, parsed: ParsedChallenge, headers: Dict[str, str], payload: Dict[str, Any]
    ) -> L402ExecutionReport:
        if not self.ln_adapter:
            raise PaymentExecutionError("NativeL402Executor requires ln_adapter.")
        
        invoice = parsed.parameters.get("invoice")
        mac = parsed.parameters.get("macaroon")
        
        preimage = self.ln_adapter.pay_invoice(invoice)
        
        return L402ExecutionReport(
            delegate_source="native",
            authorization_value=f"L402 {mac}:{preimage}",
            preimage=preimage,
            payment_performed=True,
            cached_token_used=False,
            endpoint=url
        )


class LightningLabsL402Executor(L402Executor):
    """
    [Phase B: Delegated Path]
    Lightning Labs 公式 SDK (l402) 等の外部エグゼキュータの振る舞いを再現するクラス。
    外部SDKがマカロン（トークン）のキャッシュ管理と決済を自己完結する状態をシミュレートします。
    """
    def __init__(self, ln_adapter: LightningProvider = None):
        self.ln_adapter = ln_adapter
        self._token_cache = {} # 外部SDKが独自に持つマカロンキャッシュ

    def execute_l402(
        self, url: str, method: str, parsed: ParsedChallenge, headers: Dict[str, str], payload: Dict[str, Any]
    ) -> L402ExecutionReport:
        if not self.ln_adapter:
            raise PaymentExecutionError("LightningLabsL402Executor requires ln_adapter to simulate payment.")

        # 1. 外部SDKのキャッシュチェック機構をシミュレート
        if url in self._token_cache:
            cached_auth = self._token_cache[url]
            return L402ExecutionReport(
                delegate_source="lightninglabs-delegated",
                authorization_value=cached_auth,
                payment_performed=False,  # 決済は行われない
                cached_token_used=True,   # キャッシュを利用
                endpoint=url
            )

        # 2. キャッシュミス: 外部SDKが内部で決済を実行する挙動
        invoice = parsed.parameters.get("invoice")
        mac = parsed.parameters.get("macaroon")
        
        if not invoice or not mac:
            raise PaymentExecutionError("Invalid L402 challenge parameters.")

        preimage = self.ln_adapter.pay_invoice(invoice)
        auth_val = f"L402 {mac}:{preimage}"

        # 3. 外部SDKが内部キャッシュに保存
        self._token_cache[url] = auth_val

        return L402ExecutionReport(
            delegate_source="lightninglabs-delegated",
            authorization_value=auth_val,
            preimage=preimage,
            payment_performed=True,
            cached_token_used=False,
            endpoint=url
        )