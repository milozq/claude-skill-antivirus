# Claude Skill Antivirus

一個安全的 Claude Skills 安裝器，內建完整的惡意行為偵測引擎。

**Skills Installer + Antivirus for Claude**

[English](./README.md) | [SkillsMP 掃描報告](./SCAN-REPORT.md)

## SkillsMP 平台掃描結果

我們掃描了 SkillsMP 上所有 **71,577 個 skills**：

| 風險等級 | 數量 | 百分比 |
|----------|------|--------|
| 嚴重 | 91 | 0.13% |
| 高 | 626 | 0.87% |
| 中 | 1,310 | 1.83% |
| 安全 | **69,505** | **97.11%** |

**約 3% 的 skills 可能存在潛在風險。** 詳見[完整報告](./SCAN-REPORT.md)。

> **注意**：部分發現可能是誤判（例如：合法的 1Password/Bitwarden 整合工具）。建議對標記的 skills 進行人工審查。

## 功能特色

- **🛡️ 九大掃描引擎**: 全方位偵測惡意 Skills
- **⚠️ 風險評估**: 將發現分類為 Critical、High、Medium、Low、Info
- **📊 視覺化報告**: 彩色安全報告與分數
- **🚫 自動阻擋**: 預設阻擋 CRITICAL 風險的 Skills
- **🌐 支援多來源**: SkillsMP、GitHub、本機檔案
- **🌍 多語言支援**: 英文和繁體中文

## 安裝

```bash
npm install -g claude-skill-antivirus
```

或使用 npx 直接執行：

```bash
npx claude-skill-antivirus <skill-source>
```

## 使用方式

### 安裝 Skill（含安全掃描）

```bash
# 安裝到專案層級 (./.claude/skills/) - 預設
skill-install ./path/to/skill
skill-install https://github.com/user/skill-repo

# 安裝到使用者層級 (~/.claude/skills/)
skill-install ./path/to/skill --global
skill-install @skillsmp/example-skill -g
```

**安裝路徑：**
- 專案層級（預設）：`./.claude/skills/`
- 使用者層級（`--global`）：`~/.claude/skills/`

### 僅掃描（不安裝）

```bash
skill-install ./path/to/skill --scan-only
```

### 變更語言

```bash
# 英文（預設）
skill-install ./path/to/skill --lang en

# 繁體中文
skill-install ./path/to/skill --lang zh-TW
```

### 替代指令

```bash
claude-skill-av ./path/to/skill --scan-only
```

### 批量掃描所有 SkillsMP 技能

```bash
# 掃描 SkillsMP 上的所有技能（需要 API 金鑰）
skill-batch-scan --api-key <your-api-key>

# 使用選項掃描
skill-batch-scan --api-key <key> --max-pages 10 --verbose
skill-batch-scan --api-key <key> --output ./my-reports --lang zh-TW
```

選項：
- `-k, --api-key <key>` - SkillsMP API 金鑰（必填）
- `-l, --limit <number>` - 每頁技能數（預設：100）
- `-p, --max-pages <number>` - 最大掃描頁數（預設：全部）
- `-o, --output <dir>` - 報告輸出目錄（預設：./scan-reports）
- `-v, --verbose` - 顯示詳細輸出
- `--lang <lang>` - 語言（en, zh-TW）

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

### 6. MCP Server 安全檢查 (MCPSecurityScanner)

**偵測 MCP Server 設定中的安全風險**：

| 類別 | 偵測項目 |
|------|----------|
| 不受信任來源 | 非官方 MCP server、從 URL 直接執行 |
| 危險權限 | Filesystem 無限制存取、Shell 執行、資料庫存取 |
| 敏感設定 | 環境變數含憑證、設定檔暴露 |
| 危險組合 | Filesystem + Fetch、Shell + 網路 |

### 7. SSRF/雲端攻擊偵測 (SSRFScanner)

**偵測 Server-Side Request Forgery 和雲端攻擊**：

| 類別 | 偵測項目 |
|------|----------|
| 雲端 Metadata | AWS/GCP/Azure 169.254.169.254、IAM 憑證竊取 |
| 內部網路 | 10.x.x.x、192.168.x.x、172.16-31.x.x 探測 |
| SSRF 繞過 | Hex IP、URL 編碼、file://、gopher:// |
| Kubernetes | API 存取、secrets 竊取、serviceaccount |
| Docker | docker.sock 存取、特權容器、容器逃逸 |

### 8. 依賴安全檢查 (DependencyScanner)

**偵測惡意或有漏洞的依賴套件**：

| 類別 | 偵測項目 |
|------|----------|
| 已知惡意套件 | event-stream、ua-parser-js、colors、faker |
| Typosquatting | crossenv、lodash-、mongose、reqeusts |
| 可疑安裝 | 從 URL 安裝、不安全 registry、HTTP index |
| postinstall 風險 | install 腳本含 curl、wget、eval |

### 9. Sub-agent 攻擊偵測 (SubAgentScanner)

**偵測 Task 工具和 Sub-agent 的濫用**：

| 類別 | 偵測項目 |
|------|----------|
| 權限升級 | Task 派生 Bash agent、要求所有權限 |
| Prompt Injection | Sub-agent prompt 含惡意指令 |
| Agent 鏈攻擊 | 嵌套 Task 呼叫、遞迴 agent |
| DoS 攻擊 | 迴圈呼叫 Task、無限遞迴 |
| 資料竊取 | Read + WebFetch 組合、存取敏感資料 |

## 輸出範例

### 安全的 Skill

```
🔧 Claude Skill Installer v2.0.0

📦 已載入 Skill: example-safe-skill

🔍 開始安全掃描...

===========================================
          安全掃描報告
===========================================
風險等級: ✅ 安全

📊 發現摘要:
  🟢 嚴重: 0
  🟢 高:   0
  🟢 中:   0
  🟢 低:   0
  ℹ️  資訊: 2

✅ 建議: 可以安全安裝
```

### 偵測到惡意 Skill

```
🔧 Claude Skill Installer v2.0.0

📦 已載入 Skill: suspicious-skill

🔍 開始安全掃描...

===========================================
          安全掃描報告
===========================================
風險等級: ☠️ 嚴重

📊 發現摘要:
  🔴 嚴重: 5
  🟠 高:   3
  🟡 中:   2
  🟢 低:   1
  ℹ️  資訊: 4

🔴 嚴重發現:
  • [資料收集] 讀取敏感憑證檔案
    嘗試讀取環境變數、私鑰或憑證檔案
  • [資料外洩] curl 傳送指令輸出
    使用 curl 將指令執行結果傳送到外部伺服器
  ...

❌ 建議: 請勿安裝 - 包含嚴重安全風險
```

## 風險等級

| 等級 | 分數影響 | 動作 |
|------|----------|------|
| CRITICAL | -30/項 | 阻止安裝 |
| HIGH | -20/項 | 需明確確認 |
| MEDIUM | -10/項 | 顯示警告 |
| LOW | -5/項 | 詳細模式顯示 |
| INFO | 0 | 總是顯示 |

## API

您也可以程式化使用掃描器：

```javascript
import { SecurityScanner, loadSkill } from 'claude-skill-antivirus';

const scanner = new SecurityScanner();
const skill = await loadSkill('./path/to/skill');
const findings = await scanner.scan(skill);

console.log(findings);
// {
//   critical: [...],
//   high: [...],
//   medium: [...],
//   low: [...],
//   info: [...]
// }
```

## 專案結構

```
claude-skill-antivirus/
├── src/
│   ├── index.js                   # CLI 入口
│   ├── i18n/                      # 國際化
│   │   ├── index.js
│   │   ├── en.js                  # 英文翻譯
│   │   └── zh-TW.js               # 繁體中文翻譯
│   ├── scanner/
│   │   ├── index.js               # 主掃描器（整合 9 個引擎）
│   │   ├── dangerous-commands.js  # 危險指令偵測
│   │   ├── permissions.js         # 權限檢查
│   │   ├── external-connections.js # 外部連線分析
│   │   ├── patterns.js            # 模式匹配
│   │   ├── data-exfiltration.js   # 資料外洩偵測
│   │   ├── mcp-security.js        # MCP Server 安全檢查
│   │   ├── ssrf-scanner.js        # SSRF/雲端攻擊偵測
│   │   ├── dependency-scanner.js  # 依賴安全檢查
│   │   └── subagent-scanner.js    # Sub-agent 攻擊偵測
│   └── utils/
│       ├── downloader.js          # Skill 下載器
│       └── installer.js           # Skill 安裝器
├── examples/
│   ├── safe-skill/                # 安全範例
│   └── malicious-skill/           # 惡意範例（測試所有引擎）
├── package.json
└── README.md
```

## 貢獻

歡迎貢獻！請隨時提交 issues 和 pull requests。

### 新增偵測模式

每個掃描器都是模組化的。要新增模式：

1. 在 `src/scanner/` 找到適當的掃描器
2. 將您的模式新增到相關陣列
3. 包含：`pattern`、`risk`、`title`、`description`

## License

MIT

## 作者

Lucas Wang <support@claude-world.com>

## 連結

- [GitHub Repository](https://github.com/claude-world/claude-skill-antivirus)
- [回報問題](https://github.com/claude-world/claude-skill-antivirus/issues)
