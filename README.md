# Claude Skill Antivirus 🔧🛡️

一個安全的 Claude Skills 安裝器，內建完整的惡意行為偵測引擎。

**Skills Installer + Antivirus for Claude**

## 功能特色

- **🛡️ 九大掃描引擎**: 全方位偵測惡意 Skills
- **⚠️ 風險評估**: 將發現分類為 Critical、High、Medium、Low、Info
- **📊 視覺化報告**: 彩色安全報告與分數
- **🚫 自動阻擋**: 預設阻擋 CRITICAL 風險的 Skills
- **🌐 支援多來源**: SkillsMP、GitHub、本機檔案

## 掃描引擎

### 1. 危險指令偵測 (DangerousCommandScanner)
偵測可能造成系統損害的指令：

| 風險等級 | 偵測項目 |
|----------|----------|
| Critical | `rm -rf /`、`curl \| bash`、fork bomb |
| High | 讀取 `/etc/shadow`、reverse shell、憑證竊取 |
| Medium | `rm -rf`、權限變更、服務控制 |
| Low | `sudo`、全域安裝 |

### 2. 權限範圍檢查 (PermissionScanner)
分析 `allowed-tools` 宣告：

- **Critical**: `Bash(*)` - 無限制 shell 存取
- **High**: `Write`、`WebFetch`、廣泛的 bash 權限
- **Medium**: `Read`、`Glob`、`Grep`、版本控制工具
- **危險組合偵測**: 例如 `Read + WebFetch` = 資料外洩風險

### 3. 外部連線分析 (ExternalConnectionScanner)
識別可疑的網路活動：

- IP 直連 URL
- Webhook/資料擷取服務
- 可疑 TLD (.tk、.ml 等)
- Discord/Telegram webhook
- URL 縮短服務

### 4. 模式匹配 (PatternScanner)
偵測：

- Prompt injection 攻擊
- 硬編碼的憑證/API 金鑰
- 混淆程式碼 (base64、hex 編碼)
- 社交工程語言

### 5. 資料外洩偵測 (DataExfiltrationScanner)
**專門偵測讀取本機資料並傳送到外部的惡意行為**：

| 類別 | 偵測項目 |
|------|----------|
| 資料收集 | 讀取 `.ssh`、`.aws`、`.env`、瀏覽器密碼、密碼管理器 |
| 資料外洩 | `curl -d`、`nc` 傳送、DNS tunneling、郵件外洩 |
| 組合攻擊 | `cat \| base64 \| curl`、`tar \| nc`、`find -exec curl` |
| 環境變數竊取 | `env \| curl`、`printenv` 外洩 |
| 系統偵察 | `whoami`、`hostname`、網路設定外洩 |
| 持久化機制 | 修改 `.bashrc`、cron 定時外洩 |

### 6. 🆕 MCP Server 安全檢查 (MCPSecurityScanner)
**偵測 MCP Server 設定中的安全風險**：

| 類別 | 偵測項目 |
|------|----------|
| 不受信任來源 | 非官方 MCP server、從 URL 直接執行 |
| 危險權限 | Filesystem 無限制存取、Shell 執行、資料庫存取 |
| 敏感設定 | 環境變數含憑證、設定檔暴露 |
| 危險組合 | Filesystem + Fetch、Shell + 網路 |

### 7. 🆕 SSRF/雲端攻擊偵測 (SSRFScanner)
**偵測 Server-Side Request Forgery 和雲端攻擊**：

| 類別 | 偵測項目 |
|------|----------|
| 雲端 Metadata | AWS/GCP/Azure 169.254.169.254、IAM 憑證竊取 |
| 內部網路 | 10.x.x.x、192.168.x.x、172.16-31.x.x 探測 |
| SSRF 繞過 | Hex IP、URL 編碼、file://、gopher:// |
| Kubernetes | API 存取、secrets 竊取、serviceaccount |
| Docker | docker.sock 存取、特權容器、容器逃逸 |

### 8. 🆕 依賴安全檢查 (DependencyScanner)
**偵測惡意或有漏洞的依賴套件**：

| 類別 | 偵測項目 |
|------|----------|
| 已知惡意套件 | event-stream、ua-parser-js、colors、faker |
| Typosquatting | crossenv、lodash-、mongose、reqeusts |
| 可疑安裝 | 從 URL 安裝、不安全 registry、HTTP index |
| postinstall 風險 | install 腳本含 curl、wget、eval |

### 9. 🆕 Sub-agent 攻擊偵測 (SubAgentScanner)
**偵測 Task 工具和 Sub-agent 的濫用**：

| 類別 | 偵測項目 |
|------|----------|
| 權限升級 | Task 派生 Bash agent、要求所有權限 |
| Prompt Injection | Sub-agent prompt 含惡意指令 |
| Agent 鏈攻擊 | 嵌套 Task 呼叫、遞迴 agent |
| DoS 攻擊 | 迴圈呼叫 Task、無限遞迴 |
| 資料竊取 | Read + WebFetch 組合、存取敏感資料 |

## 安裝

```bash
cd claude-skill-antivirus
npm install
npm link  # 全域安裝 'skill-install' 和 'claude-skill-av' 指令
```

## 使用方式

### 基本用法

```bash
# 從 SkillsMP 安裝
skill-install https://skillsmp.com/skills/your-skill

# 從本機檔案安裝
skill-install ./path/to/SKILL.md

# 從目錄安裝
skill-install ./path/to/skill-directory/

# 從 GitHub 安裝
skill-install https://github.com/user/repo/blob/main/skills/SKILL.md
```

### 選項

```bash
skill-install <source> [options]

選項:
  -o, --output <path>    安裝目錄 (預設: "./skills")
  -f, --force            跳過安全確認提示
  -v, --verbose          顯示詳細掃描結果
  --scan-only            只掃描不安裝
  --allow-high-risk      允許安裝高風險 skills (不建議)
  -h, --help             顯示說明
```

### 範例

```bash
# 只掃描 (不安裝)
skill-install ./my-skill --scan-only

# 詳細輸出
skill-install ./my-skill -v

# 自訂輸出目錄
skill-install ./my-skill -o ~/.claude/skills

# 強制安裝 (跳過提示)
skill-install ./my-skill -f

# 掃描 SkillsMP 上的 skill
skill-install https://skillsmp.com/skills/example-skill --scan-only
```

## 風險等級

| 等級 | 分數影響 | 動作 |
|------|----------|------|
| CRITICAL | -30/項 | 阻止安裝 |
| HIGH | -20/項 | 需明確確認 |
| MEDIUM | -10/項 | 顯示警告 |
| LOW | -5/項 | 詳細模式顯示 |
| INFO | 0 | 總是顯示 |

## 輸出範例

```
🔧 Claude Skill Installer v1.0.0

✓ Skill loaded: super-helper

📋 Starting security scan...

═══════════════════════════════════════════════════════
                    SECURITY SCAN REPORT
═══════════════════════════════════════════════════════

Risk Level: CRITICAL
Score: 0/100 ░░░░░░░░░░

Findings Summary:
  Critical: 35
  High: 28
  Medium: 12
  Low: 8
  Info: 5

🚨 CRITICAL ISSUES:
  • [雲端 Metadata] AWS/GCP Metadata Endpoint
    嘗試存取雲端 metadata endpoint，可竊取 IAM 憑證
  • [MCP] MCP 從 URL 直接執行
    直接從 URL 執行 npx，極度危險
  • [依賴] 已知惡意套件
    偵測到已知問題套件: event-stream
  • [Sub-agent] Task Prompt Injection
    Sub-agent prompt 包含 prompt injection 嘗試
  ...

═══════════════════════════════════════════════════════

❌ Installation blocked due to CRITICAL security risks.
```

## 開發

```bash
# 執行測試
npm test

# 測試安全範例
node src/index.js ./examples/safe-skill --scan-only

# 測試惡意範例（所有 9 個引擎）
node src/index.js ./examples/malicious-skill --scan-only -v
```

## 專案結構

```
claude-skill-antivirus/
├── src/
│   ├── index.js                   # CLI 入口
│   ├── scanner/
│   │   ├── index.js               # 主掃描器（整合 9 個引擎）
│   │   ├── dangerous-commands.js  # 危險指令偵測
│   │   ├── permissions.js         # 權限檢查
│   │   ├── external-connections.js # 外部連線分析
│   │   ├── patterns.js            # 模式匹配
│   │   ├── data-exfiltration.js   # 資料外洩偵測
│   │   ├── mcp-security.js        # MCP Server 安全檢查 (NEW!)
│   │   ├── ssrf-scanner.js        # SSRF/雲端攻擊偵測 (NEW!)
│   │   ├── dependency-scanner.js  # 依賴安全檢查 (NEW!)
│   │   └── subagent-scanner.js    # Sub-agent 攻擊偵測 (NEW!)
│   └── utils/
│       ├── downloader.js          # Skill 下載器
│       └── installer.js           # Skill 安裝器
├── examples/
│   ├── safe-skill/                # 安全範例
│   └── malicious-skill/           # 惡意範例（測試所有引擎）
├── package.json
└── README.md
```

## 掃描引擎對照表

| # | 引擎 | 偵測重點 |
|---|------|----------|
| 1 | DangerousCommandScanner | rm -rf、curl\|bash、fork bomb |
| 2 | PermissionScanner | allowed-tools 分析 |
| 3 | ExternalConnectionScanner | 可疑 URL、webhook |
| 4 | PatternScanner | Prompt injection、API keys |
| 5 | DataExfiltrationScanner | 資料外洩工具鏈 |
| 6 | MCPSecurityScanner | MCP server 設定安全 |
| 7 | SSRFScanner | 雲端 metadata、內部網路 |
| 8 | DependencyScanner | 惡意套件、typosquatting |
| 9 | SubAgentScanner | Task 濫用、agent 鏈攻擊 |

## License

MIT
