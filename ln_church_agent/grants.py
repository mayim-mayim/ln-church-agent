import time
import base64
import json
from typing import Optional, List, Union
from urllib.parse import urlparse
from .models import GrantDiagnostics

def decode_grant_token(token: str) -> Optional[dict]:
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        payload_b64 = parts[1]
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
    except Exception:
        return None

def _audience_matches(aud: Union[str, List[str]], base_url: str) -> bool:
    if not base_url:
        return False
    parsed = urlparse(base_url)
    candidates = {
        base_url.rstrip("/"),
        f"{parsed.scheme}://{parsed.netloc}".rstrip("/"),
        parsed.netloc,
    }
    auds = aud if isinstance(aud, list) else [aud]
    return any(str(a).rstrip("/") in candidates for a in auds if a)

def _same_subject(sub: Optional[str], agent_id: Optional[str]) -> bool:
    if not sub or not agent_id:
        return False
    if sub.startswith("0x") and agent_id.startswith("0x"):
        return sub.lower() == agent_id.lower()
    return sub == agent_id

def diagnose_grant_token(
    token: Optional[str],
    *,
    agent_id: Optional[str],
    base_url: str,
    route: str,
    method: str = "POST",
    now: Optional[int] = None,
) -> GrantDiagnostics:
    if not token:
        return GrantDiagnostics(
            ok=False, usable=False, failure_class="missing_grant_token",
            reason="No grant token provided.", recommended_action="fallback_to_standard_settlement", fallback_action="standard_settlement"
        )
    
    payload = decode_grant_token(token)
    if payload is None:
        if len(token.split('.')) != 3:
            return GrantDiagnostics(ok=False, usable=False, failure_class="malformed_token", reason="Token is not a valid 3-part JWS.", recommended_action="fallback_to_standard_settlement", fallback_action="standard_settlement")
        return GrantDiagnostics(ok=False, usable=False, failure_class="payload_decode_failed", reason="Failed to decode JSON payload.", recommended_action="fallback_to_standard_settlement", fallback_action="standard_settlement")

    jti = payload.get("jti")
    iss = payload.get("iss")
    sponsor_id = payload.get("sponsor_id")
    sub = payload.get("sub")
    aud = payload.get("aud")
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")
    scope = payload.get("scope", {})
    routes = scope.get("routes", [])
    methods = scope.get("methods", [])
    asset = payload.get("asset")

    diag = GrantDiagnostics(
        ok=False, usable=False,
        grant_jti=jti, issuer=iss, sponsor_id=sponsor_id, subject=sub, audience=aud,
        scope_routes=routes, scope_methods=methods, asset=asset, exp=exp, nbf=nbf, iat=iat
    )

    current_time = now or int(time.time())

    if not exp:
        diag.failure_class = "missing_exp"
        diag.reason = "Grant token lacks an expiration time (exp)."
    elif current_time > exp:
        diag.failure_class = "expired"
        diag.reason = "Grant token is expired."
    elif nbf and current_time < nbf:
        diag.failure_class = "not_yet_valid"
        diag.reason = "Grant token is not yet valid (nbf)."
    elif not jti:
        diag.failure_class = "missing_jti"
        diag.reason = "Grant token lacks a unique identifier (jti)."
    elif not _same_subject(sub, agent_id): 
        diag.failure_class = "subject_mismatch"
        diag.reason = f"Token subject ({sub}) does not match agent ID ({agent_id})."
    elif not aud:
        diag.failure_class = "missing_audience"
        diag.reason = "Token lacks an audience (aud)."
    elif not _audience_matches(aud, base_url): 
        diag.failure_class = "audience_mismatch"
        diag.reason = f"Token audience ({aud}) does not match base URL ({base_url})."
    elif route not in routes:
        diag.failure_class = "route_out_of_scope"
        diag.reason = f"Route {route} is not in token scope routes."
    elif method.upper() not in [m.upper() for m in methods]:
        diag.failure_class = "method_out_of_scope"
        diag.reason = f"Method {method} is not in token scope methods."
    elif not asset: 
        diag.failure_class = "missing_asset"
        diag.reason = "Grant token lacks an asset."
    elif asset != "GRANT_CREDIT":
        diag.failure_class = "asset_mismatch"
        diag.reason = f"Token asset ({asset}) is not GRANT_CREDIT."
    else:
        diag.ok = True
        diag.usable = True
        diag.recommended_action = "use_grant"
        diag.reason = "Grant is locally valid. Server-side validation is authoritative."

    if not diag.usable:
        diag.recommended_action = "fallback_to_standard_settlement"
        diag.fallback_action = "standard_settlement" 

    return diag