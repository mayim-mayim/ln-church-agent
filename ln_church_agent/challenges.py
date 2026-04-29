import base64
import json
import re
import httpx
from typing import Optional

from .models import ParsedChallenge, ChallengeSource, SchemeType
from .exceptions import PaymentChallengeError

def b64url_decode_json(b64_str: str) -> dict:
    try:
        padded = b64_str + '=' * (-len(b64_str) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        decoded = json.loads(decoded_bytes.decode('utf-8'))
        return decoded if isinstance(decoded, dict) else {}
    except Exception:
        return {}

def b64url_encode_json(data_dict: dict) -> str:
    json_str = json.dumps(data_dict)
    b64_bytes = base64.urlsafe_b64encode(json_str.encode('utf-8'))
    return b64_bytes.decode('utf-8').rstrip('=')

def normalize_scheme(raw_scheme: str) -> str:
    s = raw_scheme.lower()
    if s == "x402-direct": return SchemeType.lnc_evm_transfer.value
    if s == "x402-solana": return SchemeType.lnc_solana_transfer.value
    if s == "x402-relay":  return SchemeType.lnc_evm_relay.value
    if s == "x402": return SchemeType.x402.value
    return raw_scheme

def parse_legacy_header(header_val: str) -> ParsedChallenge:
    params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', header_val)}
    return ParsedChallenge(
        scheme=params.get("scheme", "unknown"),
        network=params.get("network", "unknown"),
        amount=float(params.get("amount", 0)),
        asset=params.get("asset", "USDC"),
        parameters=params,
        source=ChallengeSource.LEGACY_CUSTOM,
        raw_header=header_val
    )

def parse_www_authenticate(auth_header: str, source: ChallengeSource = ChallengeSource.STANDARD_WWW) -> ParsedChallenge:
    parts = auth_header.split(" ", 1)
    scheme = parts[0]
    params = {}
    if len(parts) > 1:
        params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', parts[1])}
        
    draft_shape = "unknown-payment-shape"
    payment_method = "unknown"
    payment_intent = "unknown"
    request_b64_present = False
    decoded_request_valid = False
    parsed_amount = 0.0   
    parsed_asset = "SATS" 

    if scheme in ["Payment", "MPP"]:
        if "invoice" in params and "request" not in params:
            draft_shape = "legacy-mpp-flat"
        
        req_json = {}
        if "request" in params:
            request_b64_present = True
            req_json = b64url_decode_json(params["request"])
            
            if req_json:
                decoded_request_valid = True
                params["request_json"] = req_json 
                
                has_required = all(k in params for k in ["id", "method", "intent", "request"])
                draft_shape = "payment-auth-draft" if has_required else "payment-auth-draft-partial"
                
                invoice = req_json.get("methodDetails", {}).get("invoice") or req_json.get("invoice")
                if invoice:
                    params["invoice"] = invoice

                if "amount" in req_json:
                    try:
                        parsed_amount = float(req_json["amount"])
                    except (ValueError, TypeError): 
                        pass
                
                if "currency" in req_json:
                    currency = str(req_json["currency"]).upper()
                    if currency in ["SAT", "SATS"]:
                        parsed_asset = "SATS"
                    elif currency in ["USDC", "USD"]:
                        parsed_asset = "USDC"
                    else:
                        parsed_asset = currency
            else:
                draft_shape = "payment-auth-draft-invalid-request"
        
        method_val = params.get("method") or req_json.get("method")
        if method_val:
            payment_method = method_val
        elif params.get("invoice", "").startswith(("lnbc", "lntb")):
            payment_method = "lightning"
            
        intent_val = params.get("intent") or req_json.get("intent")
        if intent_val:
            payment_intent = intent_val
        elif draft_shape == "legacy-mpp-flat":
            payment_intent = "charge"

    return ParsedChallenge(
        scheme=scheme,
        network="Lightning",
        amount=parsed_amount, 
        asset=parsed_asset,   
        parameters=params,
        source=source,
        raw_header=auth_header,
        draft_shape=draft_shape,
        payment_method=payment_method,
        payment_intent=payment_intent,
        request_b64_present=request_b64_present,
        decoded_request_valid=decoded_request_valid
    )

SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

def parse_challenge_from_response(
    response: httpx.Response, 
    expected_asset: str = "USDC", 
    expected_chain_id: Optional[str] = None,
    allowed_networks: Optional[list] = None,  # 追加: Policy由来の許可ネットワーク
    prefer_svm: bool = False                  # 追加: signer有無による優先フラグ
) -> ParsedChallenge:
    h = response.headers
    auth_h = h.get("WWW-Authenticate", "")
    if auth_h.upper().startswith(("L402", "PAYMENT", "MPP")):
        return parse_www_authenticate(auth_h, source=ChallengeSource.STANDARD_WWW)

    if "PAYMENT-REQUIRED" in h:
        val = h["PAYMENT-REQUIRED"]
        payload = b64url_decode_json(val)
        if payload:
            accepted_params = {}
            if "accepts" in payload and isinstance(payload["accepts"], list):
                
                # 1. 許可されたネットワークのみに絞り込む
                valid_accepts = payload["accepts"]
                if allowed_networks:
                    valid_accepts = [opt for opt in valid_accepts if opt.get("network") in allowed_networks]

                selected_accept = None
                
                # 2. 明示的な expected_chain_id があれば EVM 優先
                if expected_chain_id:
                    target_network = f"eip155:{expected_chain_id}"
                    selected_accept = next((opt for opt in valid_accepts if opt.get("network") == target_network), None)

                # 3. SVM (Solana) サインが利用可能なら優先して探す
                if not selected_accept and prefer_svm:
                    selected_accept = next((opt for opt in valid_accepts if str(opt.get("network", "")).startswith("solana:")), None)

                # 4. 該当がない場合は安全な候補の先頭、あるいは元の配列の先頭にフォールバック
                if not selected_accept and len(valid_accepts) > 0:
                    selected_accept = valid_accepts[0]
                elif not selected_accept and len(payload["accepts"]) > 0:
                    selected_accept = payload["accepts"][0]

                if selected_accept:
                    raw_asset = selected_accept.get("asset", expected_asset)
                    raw_amount = selected_accept.get("amount", 0)
                    logical_asset = raw_asset
                    extracted_token = ""

                    if isinstance(raw_asset, str) and raw_asset.startswith("0x"):
                        extracted_token = raw_asset
                        logical_asset = expected_asset
                    # 要件6: Solana USDC mint address を論理asset `USDC` に正規化
                    elif raw_asset == SOLANA_USDC_MINT:
                        extracted_token = raw_asset
                        logical_asset = "USDC"

                    human_amount = float(raw_amount)
                    if logical_asset == "USDC":
                        if human_amount >= 100: human_amount /= 1_000_000
                    elif logical_asset == "JPYC":
                        if human_amount >= 10000: human_amount /= 10**18

                    accepted_params = {
                        "scheme": selected_accept.get("scheme", "exact"),
                        "network": selected_accept.get("network", "unknown"),
                        "amount": human_amount,
                        "asset": logical_asset,
                        "payTo": selected_accept.get("payTo", ""),
                        "token_address": extracted_token,
                        "_raw_accepted": selected_accept,
                        "_raw_resource": payload.get("resource", {}),
                        "_raw_extensions": payload.get("extensions")
                    }

            params = {
                "network": payload.get("network") or accepted_params.get("network", "unknown"),
                "amount": payload.get("amount") or accepted_params.get("amount", 0),
                "asset": payload.get("asset") or accepted_params.get("asset", expected_asset),
                "destination": payload.get("destination") or accepted_params.get("payTo", ""),
                "payTo": payload.get("payTo") or accepted_params.get("payTo", ""),
                "token_address": payload.get("token_address") or accepted_params.get("token_address", ""),
                "challenge": payload.get("challenge", ""),
                "_raw_accepted": accepted_params.get("_raw_accepted"),
                "_raw_resource": accepted_params.get("_raw_resource"),
                "_raw_extensions": accepted_params.get("_raw_extensions")
            }
            params["amount"] = accepted_params.get("amount", params["amount"])

            return ParsedChallenge(
                scheme=payload.get("scheme") or accepted_params.get("scheme") or "x402",
                network=params["network"],
                amount=float(params["amount"]),
                asset=params["asset"],
                parameters=params,
                source=ChallengeSource.STANDARD_X402,
                raw_header=val
            )

        params = {k.strip(): v.strip('"') for k, v in re.findall(r'(\w+)="?([^",]+)"?', val)}
        if params:
            return ParsedChallenge(
                scheme=params.get("scheme", "x402"),
                network=params.get("network", "unknown"),
                amount=float(params.get("amount", 0)),
                asset=params.get("asset", expected_asset),
                parameters=params,
                source=ChallengeSource.STANDARD_X402,
                raw_header=val
            )

    try:
        body = response.json()
        if "challenge" in body:
            c = body["challenge"]
            return ParsedChallenge(
                scheme=c.get("scheme"),
                network=c.get("network"),
                amount=float(c.get("amount", 0)),
                asset=c.get("asset"),
                parameters=c.get("parameters", {}),
                source=ChallengeSource.BODY_CHALLENGE
            )
    except Exception:
        pass

    if "x-402-payment-required" in h:
        return parse_legacy_header(h["x-402-payment-required"])

    raise PaymentChallengeError("No valid 402 challenge found in headers or body.")