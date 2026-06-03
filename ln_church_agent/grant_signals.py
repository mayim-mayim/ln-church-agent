import httpx
from typing import List, Set
from .models import GrantSignalObservation

STRONG_TERMS = {
    "grant", "grants", "grant_available", "grantavailable", "sponsored_access",
    "sponsoredaccess", "access_grant", "faucet", "trial_credit", "trialcredit",
    "free_credits", "freecredits", "developer_credit", "developercredit",
    "promotional_credit", "promo_credit", "credit_grant", "entitlement",
    "redemption_endpoint", "grant_endpoint", "verification_endpoint",
    "verify_grant", "eligibility", "scope", "expires_at", "transferable",
    "requires_identity"
}

WEAK_TERMS = {
    "coupon", "discount", "promo", "promotion", "loyalty", "reward",
    "points", "free trial", "trial", "credit", "sponsor", "sponsored"
}

FALSE_POSITIVE_PHRASES = [
    "grant permission", "data points", "reward model", "credit card"
]

def _is_sensitive_key(key: str) -> bool:
    """生トークンやシークレットを避けるためのフィルタ"""
    k = key.lower()
    sensitive = {
        "grant_token", "authorization", "cookie", "api_key", "access_token", 
        "refresh_token", "secret", "private_key", "preimage", "macaroon", 
        "mandate_token", "shared_payment_token"
    }
    return any(s in k for s in sensitive)

def detect_grant_signals(response: httpx.Response) -> GrantSignalObservation:
    obs = GrantSignalObservation()
    
    body_json = None
    try:
        if response.content:
            body_json = response.json()
            if isinstance(body_json, dict):
                obs.source_kinds.append("body_json")
                obs.machine_readable = True
    except Exception:
        pass

    text_content = ""
    try:
        if not body_json and response.content:
            text_content = response.text.lower()
    except Exception:
        pass

    detected_strong: Set[str] = set()
    detected_weak: Set[str] = set()
    detected_fields: Set[str] = set()
    is_oauth = False

    # Check headers (実際に検出した時のみ source_kinds に入れる)
    found_in_headers = False
    if response.headers:
        for k, v in response.headers.items():
            kl = k.lower()
            if _is_sensitive_key(kl):
                continue
            
            for st in STRONG_TERMS:
                if st in kl: 
                    detected_strong.add(st)
                    detected_fields.add(k)
                    found_in_headers = True
            for wt in WEAK_TERMS:
                if wt in kl: 
                    detected_weak.add(wt)
                    detected_fields.add(k)
                    found_in_headers = True
                    
    if found_in_headers and "headers" not in obs.source_kinds:
        obs.source_kinds.append("headers")

    # 2. Check JSON
    def _traverse_json(obj: any, prefix: str = ""):
        nonlocal is_oauth
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                
                # bool値が明示されていれば優先して保持する
                if kl == "transferable" and isinstance(v, bool):
                    obs.transferability_declared = v
                if kl == "requires_identity" and isinstance(v, bool):
                    obs.requires_identity = v
                
                if kl == "grant_type":
                    is_oauth = True
                
                if _is_sensitive_key(kl):
                    continue
                    
                for st in STRONG_TERMS:
                    if st in kl: 
                        detected_strong.add(st)
                        detected_fields.add(k)
                for wt in WEAK_TERMS:
                    if wt in kl: 
                        detected_weak.add(wt)
                        detected_fields.add(k)
                
                if isinstance(v, str):
                    vl = v.lower()
                    if kl == "grant_type" and vl in {"client_credentials", "authorization_code", "refresh_token"}:
                        is_oauth = True
                        
                    # 値が長すぎる場合は本文として扱い、フィールド抽出は避ける
                    if len(vl) < 100:
                        # JSON Value に対しては強いシグナルのみを抽出する（誤検知防止）
                        for st in STRONG_TERMS:
                            if st in vl: detected_strong.add(st)
                            
                _traverse_json(v, prefix=f"{prefix}.{k}" if prefix else k)
        elif isinstance(obj, list):
            for item in obj:
                _traverse_json(item, prefix)

    if body_json:
        _traverse_json(body_json)
    elif text_content and len(text_content) < 5000:
        # 3. Check short text body
        if "body_text" not in obs.source_kinds:
            obs.source_kinds.append("body_text")
            
        for fp in FALSE_POSITIVE_PHRASES:
            text_content = text_content.replace(fp, "")
            
        for st in STRONG_TERMS:
            if st in text_content: detected_strong.add(st)
        for wt in WEAK_TERMS:
            if wt in text_content: detected_weak.add(wt)

    # False Positive Guard: OAuth
    if is_oauth:
        oauth_related = {"grant", "grant_type", "token_type", "expires_at", "scope"}
        strong_non_oauth = detected_strong - oauth_related
        if not strong_non_oauth and not detected_weak:
            return GrantSignalObservation(detected=False, confidence="none")

    all_terms = list(detected_strong | detected_weak)
    if not all_terms:
        return GrantSignalObservation(detected=False, confidence="none")

    # Determine confidence
    if len(detected_strong) >= 2:
        obs.confidence = "high"
    elif len(detected_strong) == 1:
        obs.confidence = "medium"
    elif len(detected_weak) >= 2:
        obs.confidence = "medium"
    else:
        obs.confidence = "low"

    obs.detected = True
    obs.detected_terms = sorted(list(detected_strong | detected_weak))
    obs.detected_fields = sorted(list(detected_fields))

    # Determine Signal Types
    st_str = " ".join(obs.detected_terms)
    df_str = " ".join(obs.detected_fields).lower()
    
    if "faucet" in st_str or "faucet" in df_str: obs.signal_types.append("faucet")
    if "trial_credit" in st_str or "free_credits" in st_str: obs.signal_types.append("trial_credit")
    if "developer_credit" in st_str: obs.signal_types.append("developer_credit")
    if "promotional_credit" in st_str or "promo_credit" in st_str: obs.signal_types.append("promotional_credit")
    if "coupon" in st_str or "discount" in st_str: obs.signal_types.append("coupon_or_discount")
    if "loyalty" in st_str or "reward" in st_str: obs.signal_types.append("loyalty_reward")
    if "entitlement" in st_str or "access_grant" in st_str: obs.signal_types.append("access_entitlement")
    if "sponsored" in st_str or "sponsor" in st_str: obs.signal_types.append("sponsored_grant")
    
    if not obs.signal_types:
        if "grant" in st_str or "grant" in df_str:
            obs.signal_types.append("unknown_grant_like")

    # Map flags
    if "redemption_endpoint" in df_str or "grant_endpoint" in df_str:
        obs.redemption_endpoint_present = True
    if "verification_endpoint" in df_str or "verify_grant" in df_str:
        obs.verification_endpoint_present = True
    if "eligibility" in df_str: obs.eligibility_declared = True
    if "scope" in df_str: obs.scope_declared = True
    if "expires_at" in df_str: obs.expiration_declared = True
    
    # bool値がJSON側で取れていなければTrueにする
    if "transferable" in df_str and obs.transferability_declared is None:
        obs.transferability_declared = True
    if "requires_identity" in df_str and obs.requires_identity is None:
        obs.requires_identity = True

    return obs