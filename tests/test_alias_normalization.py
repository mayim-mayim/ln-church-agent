import pytest
from ln_church_agent.client import _normalize_scheme
from ln_church_agent.models import SchemeType

def test_legacy_alias_normalization():
    """旧語彙（レガシーエイリアス）が正しいcanonical名に変換されることを確認"""
    
    # EVM Direct -> Transfer
    assert _normalize_scheme("x402-direct") == SchemeType.lnc_evm_transfer.value
    # Solana -> Solana Transfer
    assert _normalize_scheme("x402-solana") == SchemeType.lnc_solana_transfer.value
    # 独自 Relay -> EVM Relay
    assert _normalize_scheme("x402-relay") == SchemeType.lnc_evm_relay.value

def test_standard_scheme_passthrough():
    """標準語彙（x402, L402）はそのまま通過することを確認"""
    
    # 大文字小文字の違いはあれど、値としてはそのまま返るか
    assert _normalize_scheme("x402") == "x402"
    assert _normalize_scheme("L402") == "L402"
    assert _normalize_scheme("MPP") == "MPP"

def test_case_insensitivity():
    """大文字で入力されても正しく小文字ベースで判定・正規化されるかを確認"""
    
    assert _normalize_scheme("X402-DIRECT") == SchemeType.lnc_evm_transfer.value
    assert _normalize_scheme("X402-SOLANA") == SchemeType.lnc_solana_transfer.value