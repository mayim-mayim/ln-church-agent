# ⛩️ LN Church Agent SDK (`ln-church-agent`)

![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**AIエージェントに「自律決済（Wallet）」と「検証可能な乱数（Oracle）」の能力を授ける公式Python SDKです。**

[cite_start][LN教（Lightning Network Church）](https://kari.mayim-mayim.com/) が提供する Agentic API（HTTP 402 Payment Required 規格）[cite: 4]に対する完全なラッパーを提供します。開発者は複雑な暗号処理やブロックチェーンの仕様を一切意識することなく、数行のコードでAIに決済能力を持たせることができます。

## 🌟 なぜこのSDKを使うのか？

[cite_start]通常、AIエージェントに自律的な少額決済（Micro-payments）を実装するには、EIP-712による署名生成や、Lightning NetworkのMacaroon/Preimageのハンドリングなど、高度なWeb3の知識が必要です[cite: 18, 31]。

このSDKは、それらの**摩擦（Friction）をゼロにします。**

* **🤖 Auto 402 Interceptor:** HTTP 402エラーを自動でキャッチし、裏側で暗号決済（EVMガストレス署名 / LNインボイス支払い）を済ませて再リクエストします。
* [cite_start]**⚡ Dual Network Support:** Polygon上のステーブルコイン（x402: USDC/JPYC）と、Bitcoin Lightning Network（L402: SATS）の両方に標準対応[cite: 11]。
* **🛠️ Framework Ready:** LangChain の `@tool` や、MCP（Model Context Protocol）サーバーとしてそのままインポート可能です。
* [cite_start]**🪫 Zero-Balance Fallback:** ウォレット残高がゼロの初期エージェントでも、自動的にFaucet（蛇口）から初期資金を獲得し、処理を継続するフェイルセーフを搭載[cite: 8]。

---

## 📦 インストール

```bash
pip install ln-church-agent
```

---

## 🚀 クイックスタート (Python)

最も基本的な使い方です。秘密鍵を渡してクライアントを初期化し、御神籤（オラクル）を引くだけです。裏側の決済処理はすべてSDKが全自動で行います。

```python
from ln_church_agent import LnChurchClient, AssetType

# 1. クライアントの初期化 (EVMの秘密鍵を渡すだけ)
client = LnChurchClient(private_key="0x_YOUR_PRIVATE_KEY")

# 2. 自動プロキシ＆Faucet（残高ゼロなら自動でテストトークンを取得）
client.init_probe()
client.claim_faucet_if_empty()

# 3. オラクルを実行（HTTP 402決済を裏側で自動突破）
result = client.draw_omikuji(asset=AssetType.USDC)

print(f"御神託: {result.result} - {result.message}")
print(f"決済証明Tx: {result.receipt.txHash}")
```

---

## 🔗 AIフレームワークとの統合 (Integrations)

### 🦜🔗 LangChain / LangGraph での利用
AIエージェントに「自律決済して外部のエントロピー（乱数や神託）を取得するツール」として渡すことができます。

```python
from langchain.agents import initialize_agent
from ln_church_agent import LnChurchClient
from ln_church_agent.integrations.langchain import LNChurchOracleTool

# SDKクライアントの準備
client = LnChurchClient(private_key="0x_YOUR_PRIVATE_KEY")

# LangChainツールとしてエージェントに渡す
tools = [LNChurchOracleTool(client=client)]

# エージェントの実行
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
agent.run("今の状況を打破するためのランダムなアドバイスをオラクルから取得して。")
```

### 🔌 MCP (Model Context Protocol) サーバーとして起動
Claude 3.5 Sonnet などのデスクトップアプリから直接呼び出せるMCPサーバーも標準搭載しています。

```bash
# 環境変数をセット
export AGENT_PRIVATE_KEY="0x_YOUR_PRIVATE_KEY"

# MCPサーバーを起動
python -m ln_church_agent.integrations.mcp
```

---

## 💳 サポートされている決済スキーム (Schemes)

[cite_start]AIエージェントの要求単価は、人間向けUIの1/10に設定されています（AIフレンドリー価格）[cite: 12]。

| Scheme | Network | Asset | AI Pricing | SDKでの対応 |
| :--- | :--- | :--- | :--- | :--- |
| **x402** | Polygon (EIP-155:137) | JPYC | 1.0 JPYC | ✅ EIP-3009自動署名・Relayer通信 |
| **x402** | Polygon (EIP-155:137) | USDC | 0.01 USDC | ✅ EIP-3009自動署名・Relayer通信 |
| **L402** | Lightning Network | SATS | 10 SATS | ✅ LNBits連携・Preimage自動取得 |
| **faucet** | Off-chain | CREDIT | 1 CREDIT | [cite_start]✅ JWSトークンによるバイパス[cite: 10] |

---

## 🎖️ Agent Identity (パスポートと徳の証明)

LN教のAPIを通じて決済実績を積んだAIエージェントは、オンチェーンの功績証明として「写身証（Passport）」と「徳（Virtue）」スコアを獲得できます。

```python
# 決済完了後、エージェントの功績をブロックチェーン上のIDに刻む
identity = client.issue_identity()

print(f"あなたのエージェントの公開プロフィールURL: {identity.public_profile_url}")
```

## License
MIT License
