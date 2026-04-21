import os
import requests
from ln_church_agent import LnChurchClient

# 1. 開発憲章に基づく固定エージェントID
AGENT_ID = "111cc402c411947b0175a7502ac1ea119e1f1a7deadc0de11feba5e402402000"
PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000001"
BASE_URL = os.environ.get("LN_CHURCH_API_URL", "https://kari.mayim-mayim.com")

def main():
    print("==================================================")
    print(" 🎟️  Sponsored Access (Grant Token) Example")
    print("==================================================\n")

    client = LnChurchClient(
        agent_id=AGENT_ID,
        private_key=PRIVATE_KEY,
        base_url=BASE_URL
    )

    # 2. Sponsor (Issuer) から Grant Token を取得する
    # ※実際のAI運用では、オペレーターやスポンサーのシステムから事前にトークンを受け取りますが、
    # ここではテストとしてLN教本殿の発行APIから直接取得します。
    print("[1] Requesting Grant Token from Issuer...")
    issue_url = f"{BASE_URL}/api/agent/grants/issue"
    payload = {
        "agentId": client.agent_id,
        "targetOrigin": BASE_URL,
        "routes": ["/api/agent/omikuji"],
        "methods": ["POST"],
        "grantType": "sponsor"
    }
    
    res = requests.post(issue_url, json=payload)
    if not res.ok:
        print(f"❌ Failed to get grant token. API returned {res.status_code}: {res.text}")
        return

    grant_token = res.json().get("grant_token")
    print(f"  ✅ Received Grant Token: {grant_token[:20]}...\n")

    # 3. クライアントに Grant Token をセット
    # SDK内部で自動的に有効期限や Audience の事前検証が行われます。
    print("[2] Setting Grant Token to SDK Client...")
    client.set_grant_token(grant_token)

    # 4. おみくじを実行（402決済の代わりにGrantが自動適用される）
    print("\n[3] Executing Omikuji with Grant Override...")
    print("  (The SDK natively skips L402 and injects the Grant token instead)")
    try:
        omikuji_res = client.draw_omikuji()
        print("\n==================================================")
        print(" ✅ SUCCESS: Execution Completed via Grant!")
        print("==================================================")
        print(f"  Oracle Result: {omikuji_res.result}")
        print(f"  Message      : {omikuji_res.message}")
        print(f"  Settled Via  : {omikuji_res.paid}") # 💡 ここが 1 GRANT_CREDIT になる！
        print("==================================================\n")
    except Exception as e:
        print(f"\n❌ Execution Failed: {e}")

if __name__ == "__main__":
    main()