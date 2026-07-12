# ln_church_agent/adapters/l402_delegate.py

from typing import Dict, Any, Tuple
from ..crypto.protocols import L402Executor, LightningProvider
from ..crypto.lightning import decode_bolt11_amount_msats
from ..models import ParsedChallenge, L402ExecutionReport
from ..exceptions import PaymentExecutionError


def _validated_l402_challenge(parsed: ParsedChallenge) -> Tuple[str, str]:
    invoice = parsed.parameters.get("invoice")
    macaroon = parsed.parameters.get("macaroon")

    if not isinstance(macaroon, str):
        raise PaymentExecutionError("Fail-Closed: Invalid or missing Invoice/Macaroon.")
    normalized_macaroon = macaroon.strip()
    if (
        normalized_macaroon != macaroon
        or len(normalized_macaroon) < 10
        or normalized_macaroon.startswith("<")
        or normalized_macaroon.lower() in {"dummy", "missing", "none", "null", "placeholder"}
    ):
        raise PaymentExecutionError("Fail-Closed: Invalid or missing Invoice/Macaroon.")

    try:
        decoded_msats = decode_bolt11_amount_msats(invoice)
    except (TypeError, ValueError):
        raise PaymentExecutionError("Fail-Closed: Invalid or missing Invoice/Macaroon.") from None

    parsed_msats = getattr(parsed, "_invoice_msats", None)
    if parsed_msats is not None and parsed_msats != decoded_msats:
        raise PaymentExecutionError("Fail-Closed: Parsed invoice amount does not match BOLT11 invoice.")

    parsed_atomic_amount = getattr(parsed, "_atomic_amount", None)
    if parsed_atomic_amount is not None and parsed_atomic_amount != str(decoded_msats):
        raise PaymentExecutionError("Fail-Closed: Canonical amount does not match BOLT11 invoice.")

    canonical_requirement = getattr(parsed, "_canonical_requirement", None)
    if canonical_requirement is not None and canonical_requirement.atomic_amount != str(decoded_msats):
        raise PaymentExecutionError("Fail-Closed: Canonical requirement does not match BOLT11 invoice.")

    return invoice, macaroon


class NativeL402Executor(L402Executor):
    def __init__(self, ln_adapter: LightningProvider):
        self.ln_adapter = ln_adapter

    def execute_l402(self, url: str, method: str, parsed: ParsedChallenge, headers: Dict[str, str], payload: Dict[str, Any]) -> L402ExecutionReport:
        if not self.ln_adapter:
            raise PaymentExecutionError("Fail-Closed: NativeL402Executor requires ln_adapter.")

        invoice, mac = _validated_l402_challenge(parsed)

        # Wallet is called ONLY after validation
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

        invoice, mac = _validated_l402_challenge(parsed)

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
