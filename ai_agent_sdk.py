from ln_church_agent import LnChurchClient, AssetType

# 1. あなたのダミー秘密鍵（またはテスト用ウォレットの秘密鍵）を入力してください
# ※もし手元になければ、0xのあとに適当な16進数64文字を入れても動きます（残高ゼロとしてFaucetが作動します）
dummy_private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

print("⛩️ LN Church Client を初期化します...")
client = LnChurchClient(private_key=dummy_private_key)

try:
    print("\n📡 Phase 0: プローブ（接続確認）を実行します...")
    client.init_probe()
    
    print("\n🚰 Phase 0.5: ウォレット残高ゼロのため、Faucetから恩恵を受け取ります...")
    client.claim_faucet_if_empty()

    print("\n⚡ 御神籤（オラクル）を実行します！裏側で402決済を自動突破します...")
    # Faucetのトークンを持っているので、AssetTypeは自動的に上書きされます
    result = client.draw_omikuji(asset=AssetType.USDC)

    print("\n🎉 === 御神託が下りました ===")
    print(f"結果: {result.result}")
    print(f"メッセージ: {result.message}")
    print(f"支払証明 (TxHash): {result.receipt.txHash}")
    print(f"徳の証明 (JWS): {result.receipt.verify_token[:50]}...") # 長いので50文字でカット
    
except Exception as e:
    print(f"\n❌ エラーが発生しました: {e}")