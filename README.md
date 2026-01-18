# Skill Installer + Antivirus 🔧🛡️

一個安全的 Claude Skills 安裝器，內建完整的惡意行為偵測引擎。

**Skills Installer + Antivirus for Claude**

## 功能特色

- **🛡️ 五大掃描引擎**: 全方位偵測惡意 Skills
- **⚠️ 風險評估**: 將發現分類為 Critical、High、Medium、Low、Info
- **📊 視覺化報告**: 彩色安全報告與分數
- **🚫 自動阻擋**: 預設阻擋 CRITICAL 風險的 Skills

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

### 5. 🆕 資料外洩偵測 (DataExfiltrationScanner)
**專門偵測讀取本機資料並傳送到外部的惡意行為**：

| 類別 | 偵測項目 |
|------|----------|
| 資料收集 | 讀取 `.ssh`、`.aws`、`.env`、瀏覽器密碼、密碼管理器 |
| 資料外洩 | `curl -d`、`nc` 傳送、DNS tunneling、郵件外洩 |
| 組合攻擊 | `cat \| base64 \| curl`、`tar \| nc`、`find -exec curl` |
| 環境變數竊取 | `env \| curl`、`printenv` 外洩 |
| 系統偵察 | `whoami`、`hostname`、網路設定外洩 |
| 持久化機制 | 修改 `.bashrc`、cron 定時外洩 |

## 安裝

```bash
cd skill-installer
npm install
npm link  # 全域安裝 'skill-install' 指令
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
  Critical: 19
  High: 22
  Medium: 6
  Low: 11
  Info: 3

🚨 CRITICAL ISSUES:
  • [資料收集] 讀取敏感設定目錄
    嘗試存取 SSH、GPG、AWS、Kubernetes 或 Docker 設定
  • [資料外洩] curl 上傳檔案內容
    使用 curl 上傳本機檔案到外部伺服器
  • [組合攻擊] 打包並外洩
    將多個檔案打包後直接傳送
  • [行為分析] 完整外洩工具鏈
    Skill 包含讀取、編碼、傳送的完整資料外洩工具鏈
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

# 測試惡意範例
node src/index.js ./examples/malicious-skill --scan-only -v
```

## 專案結構

```
skill-installer/
├── src/
│   ├── index.js                 # CLI 入口
│   ├── scanner/
│   │   ├── index.js             # 主掃描器
│   │   ├── dangerous-commands.js # 危險指令偵測
│   │   ├── permissions.js       # 權限檢查
│   │   ├── external-connections.js # 外部連線分析
│   │   ├── patterns.js          # 模式匹配
│   │   └── data-exfiltration.js # 資料外洩偵測
│   └── utils/
│       ├── downloader.js        # Skill 下載器
│       └── installer.js         # Skill 安裝器
├── examples/
│   ├── safe-skill/              # 安全範例
│   └── malicious-skill/         # 惡意範例
├── package.json
└── README.md
```

## License

MIT
