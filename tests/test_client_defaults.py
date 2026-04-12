import pytest
from unittest.mock import patch
from ln_church_agent import LnChurchClient, AssetType

@patch("ln_church_agent.client.Payment402Client.execute_request")
def test_draw_omikuji_default_scheme_is_standard(mock_execute_request):
    """
    LnChurchClientのコンビニエンスメソッドが、独自仕様(lnc-evm-relay等)ではなく、
    標準仕様(x402 / L402)をデフォルトとしてペイロードを構築することを担保する。
    """
    # モックの戻り値を設定（Pydanticの型バリデーションを完全に通過する型に修正）
    mock_execute_request.return_value = {
        "status": "success",
        "result": "test_entropy",
        "message": "test_message",
        "tx_ref": "dummy_ref_123",
        "paid": "1.0",           # <- floatではなく文字列の "1.0" に修正
        "receipt": {
            "ritual": "omikuji",
            "timestamp": 1704067200,   # <- ISO文字列ではなく整数（UNIXタイム）に修正
            "txHash": "0x123",
            "verify_token": "jws",
            "paid": "1.0"        # <- floatではなく文字列の "1.0" に修正
        }
    }

    # ダミー鍵でクライアント初期化
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    # 1. 引数なし（デフォルト）の場合 -> SATS + L402 になるべき
    client.draw_omikuji()
    args, kwargs = mock_execute_request.call_args
    payload = kwargs.get("payload") or next((a for a in args if isinstance(a, dict) and "scheme" in a), {})
    assert payload.get("scheme") == "L402", f"デフォルトは 'L402' であるべきですが '{payload.get('scheme')}' が渡されました"
    assert payload.get("asset") == "SATS", f"デフォルトのアセットは 'SATS' であるべきですが '{payload.get('asset')}' が渡されました"

    # 2. USDCを指定した場合 (非SATS) -> 互換のために標準 'x402' になるべき
    client.draw_omikuji(asset=AssetType.USDC)
    args, kwargs = mock_execute_request.call_args
    payload = kwargs.get("payload") or next((a for a in args if isinstance(a, dict) and "scheme" in a), {})
    assert payload.get("scheme") == "x402", f"非SATSのデフォルトは 'x402' であるべきですが '{payload.get('scheme')}' が渡されました"

    # 3. 本殿独自の最適化ルートを明示指定した場合
    client.draw_omikuji(asset=AssetType.USDC, scheme="lnc-evm-relay")
    args, kwargs = mock_execute_request.call_args
    payload = kwargs.get("payload") or next((a for a in args if isinstance(a, dict) and "scheme" in a), {})
    assert payload.get("scheme") == "lnc-evm-relay", f"明示指定された 'lnc-evm-relay' であるべきですが '{payload.get('scheme')}' が渡されました"