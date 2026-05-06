import httpx
import re
from typing import Optional, Dict, Any
from .challenges import b64url_decode_json

def _extract_json_payloads(response: httpx.Response) -> list[Dict[str, Any]]:
    """
    HTTPレスポンスの Body および ヘッダーから潜在的なJSONペイロードを抽出する。
    WWW-Authenticate や PAYMENT-REQUIRED に埋め込まれた Base64URL JSON にも対応。
    """
    payloads = []
    
    # 1. JSON Bodyからの抽出
    try:
        body = response.json()
        if isinstance(body, dict):
            payloads.append(body)
    except Exception:
        pass

    # 2. HTTPヘッダーからの抽出
    for header, value in response.headers.items():
        h_lower = header.lower()
        if h_lower in ["payment-required", "www-authenticate", "x-agent-payment"]:
            # WWW-Authenticate: Payment request="<base64url>" などの形式に対応
            match = re.search(r'request="?([^",]+)"?', value)
            if match:
                b64_val = match.group(1)
                decoded = b64url_decode_json(b64_val)
                if decoded:
                    payloads.append(decoded)
            else:
                # PAYMENT-REQUIRED: <base64url> の形式に対応
                decoded = b64url_decode_json(value)
                if decoded:
                    payloads.append(decoded)
                    
    return payloads

def _is_x_layer_network(value: Any) -> bool:
    """X Layer ネットワークの厳密な判定"""
    s = str(value).lower().strip()
    return s in {"196", "eip155:196", "xlayer", "x-layer"}

def detect_app_surface(response: httpx.Response) -> Optional[Dict[str, Any]]:
    """
    Agent Commerce surface (OKX APP, および将来の AP2 / ACP / UCP 等) を検出・分類する。
    単独の eip3009 や appVersion では APP と判定せず、明示的なシグナルを必須とする。
    
    Returns:
        Commerce Surface と判定された場合は詳細な dict を返す。そうでない場合は None。
    """
    payloads = _extract_json_payloads(response)
    if not payloads:
        return None

    # すべてのペイロードをフラットにマージ（ヘッダーとBodyの情報を統合評価）
    merged = {}
    for p in payloads:
        merged.update(p)

    score = 0
    commerce_protocol = None
    commerce_intent = None
    settlement_method = None
    network = None
    broker_required = None
    commerce_transport = "http"
    is_explicit_signal = False

    # --- ヒューリスティック・スコアリング ---

    # 1. プロトコルの明示的宣言
    proto = merged.get("protocol") or merged.get("agentPaymentsProtocol")
    if isinstance(proto, str) and proto.lower() in ["okx-app", "agent-payments-protocol", "app"]:
        score += 50
        is_explicit_signal = True
        commerce_protocol = "okx_app"

    if "appVersion" in merged:
        score += 20

    # 2. Broker オブジェクトの存在 (Commerce Orchestration の特徴)
    broker = merged.get("broker")
    if broker and isinstance(broker, dict):
        score += 30
        is_explicit_signal = True
        req = broker.get("required")
        broker_required = bool(req) if req is not None else None

    # 3. Intent (商取引の意図)
    intent = merged.get("intent") or merged.get("paymentIntent")
    if isinstance(intent, str):
        intent_lower = intent.lower()
        commerce_intent = intent_lower
        
        # 高度な Commerce Intent の場合は明示的シグナルとみなす
        if intent_lower in ["batch", "escrow", "upto"]:
            score += 30
            is_explicit_signal = True
        elif intent_lower in ["charge", "session"]:
            score += 5

    # 4. Payment / Settlement レールの特徴 (EIP-3009, X Layer等)
    payment = merged.get("payment") or merged.get("settlement") or {}
    if not isinstance(payment, dict):
        payment = {}

    method = payment.get("method") or merged.get("method")
    if isinstance(method, str) and method.lower() == "eip3009":
        score += 10
        settlement_method = "evm_eip3009"

    net = payment.get("network") or merged.get("network") or merged.get("chainId")
    if net and _is_x_layer_network(net):
        score += 10
        network = str(net)

    # --- 判定 ---
    
    # 誤検知防止: 明示的なシグナル（protocol, broker, 高度なintent）がない場合は棄却
    if not is_explicit_signal:
        return None

    # スコアが閾値に満たない場合も棄却
    if score < 30:
        return None

    return {
        "rail": "APP",
        "commerce_protocol": commerce_protocol or "unknown_commerce_protocol",
        "commerce_intent": commerce_intent or "unknown",
        "commerce_transport": commerce_transport,
        "settlement_method": settlement_method or "unknown",
        "network": network or "unknown",
        "broker_required": broker_required,
        "raw_detected_fields": merged,
        "confidence": "high" if score >= 50 else "medium"
    }