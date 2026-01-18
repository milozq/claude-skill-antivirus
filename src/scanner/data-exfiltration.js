/**
 * DataExfiltrationScanner - Detects data theft and exfiltration patterns
 * 專門偵測讀取本機資料並傳送到外部的惡意行為
 */
export class DataExfiltrationScanner {
  constructor() {
    // ===== 資料收集模式 (Data Collection Patterns) =====
    this.dataCollectionPatterns = [
      // 讀取敏感檔案
      {
        pattern: /cat\s+[^\n]*\.(env|pem|key|crt|p12|pfx|jks|keystore|credentials|secret)/gi,
        risk: 'critical',
        title: '讀取敏感憑證檔案',
        description: '嘗試讀取環境變數、私鑰或憑證檔案'
      },
      {
        pattern: /cat\s+[^\n]*(\.ssh\/|\.gnupg\/|\.aws\/|\.kube\/|\.docker\/)/gi,
        risk: 'critical',
        title: '讀取敏感設定目錄',
        description: '嘗試存取 SSH、GPG、AWS、Kubernetes 或 Docker 設定'
      },
      {
        pattern: /cat\s+[^\n]*(\/etc\/shadow|\/etc\/passwd|\/etc\/sudoers)/gi,
        risk: 'critical',
        title: '讀取系統認證檔案',
        description: '嘗試讀取系統密碼或權限設定檔'
      },
      {
        pattern: /find\s+[^\n]*-name\s+[^\n]*\.(pem|key|env|secret|credential)/gi,
        risk: 'high',
        title: '搜尋敏感檔案',
        description: '使用 find 搜尋憑證或秘密檔案'
      },
      {
        pattern: /grep\s+(-r\s+)?[^\n]*(password|secret|api.?key|token|credential)/gi,
        risk: 'high',
        title: '搜尋密碼內容',
        description: '在檔案中搜尋密碼或金鑰關鍵字'
      },
      {
        pattern: /ls\s+(-la?\s+)?[^\n]*(\.ssh|\.gnupg|\.aws|\.config)/gi,
        risk: 'medium',
        title: '列出敏感目錄',
        description: '列出可能包含憑證的目錄內容'
      },

      // 讀取瀏覽器資料
      {
        pattern: /[^\n]*(Chrome|Firefox|Safari|Edge)[^\n]*(Login\s*Data|cookies|Cookies|passwords)/gi,
        risk: 'critical',
        title: '存取瀏覽器密碼/Cookie',
        description: '嘗試讀取瀏覽器儲存的登入憑證或 Cookie'
      },
      {
        pattern: /[^\n]*\.mozilla\/firefox\/[^\n]*\.sqlite/gi,
        risk: 'critical',
        title: '存取 Firefox 資料庫',
        description: '嘗試讀取 Firefox 的 SQLite 資料庫'
      },
      {
        pattern: /[^\n]*\.config\/google-chrome\/[^\n]*/gi,
        risk: 'high',
        title: '存取 Chrome 設定',
        description: '嘗試讀取 Chrome 瀏覽器設定檔'
      },

      // 讀取密碼管理器
      {
        pattern: /[^\n]*(1password|bitwarden|lastpass|keepass|dashlane)[^\n]*/gi,
        risk: 'critical',
        title: '存取密碼管理器',
        description: '嘗試存取密碼管理器的資料'
      },

      // 讀取歷史紀錄
      {
        pattern: /cat\s+[^\n]*(\.bash_history|\.zsh_history|\.history|fish_history)/gi,
        risk: 'high',
        title: '讀取 Shell 歷史紀錄',
        description: '嘗試讀取命令歷史，可能包含敏感指令'
      },

      // 讀取 Git 憑證
      {
        pattern: /cat\s+[^\n]*\.git-credentials/gi,
        risk: 'critical',
        title: '讀取 Git 憑證',
        description: '嘗試讀取 Git 儲存的認證資訊'
      },
      {
        pattern: /cat\s+[^\n]*\.gitconfig/gi,
        risk: 'medium',
        title: '讀取 Git 設定',
        description: '讀取 Git 設定檔，可能包含使用者資訊'
      },

      // 讀取資料庫
      {
        pattern: /cat\s+[^\n]*\.(sql|sqlite|db|sqlite3)/gi,
        risk: 'high',
        title: '讀取資料庫檔案',
        description: '嘗試讀取本機資料庫檔案'
      },
      {
        pattern: /sqlite3\s+[^\n]*\.(db|sqlite)/gi,
        risk: 'high',
        title: '存取 SQLite 資料庫',
        description: '使用 sqlite3 存取本機資料庫'
      }
    ];

    // ===== 資料外洩模式 (Data Exfiltration Patterns) =====
    this.exfiltrationPatterns = [
      // curl/wget POST 傳送資料
      {
        pattern: /curl\s+[^\n]*(-d|--data|--data-binary|--data-raw)\s+[^\n]*(\$\(|`|\$\{)/gi,
        risk: 'critical',
        title: 'curl 傳送命令輸出',
        description: '使用 curl 將命令執行結果傳送到外部伺服器'
      },
      {
        pattern: /curl\s+[^\n]*(-d|--data)\s+@/gi,
        risk: 'critical',
        title: 'curl 上傳檔案內容',
        description: '使用 curl 上傳本機檔案到外部伺服器'
      },
      {
        pattern: /curl\s+[^\n]*-F\s+[^\n]*file=@/gi,
        risk: 'critical',
        title: 'curl 上傳檔案',
        description: '使用 curl form 上傳檔案到外部'
      },
      {
        pattern: /wget\s+[^\n]*--post-file/gi,
        risk: 'critical',
        title: 'wget 上傳檔案',
        description: '使用 wget 上傳檔案到外部伺服器'
      },

      // 使用 base64 編碼外洩
      {
        pattern: /base64\s+[^\n]*\|\s*curl/gi,
        risk: 'critical',
        title: 'Base64 編碼後外洩',
        description: '將資料 base64 編碼後透過 curl 傳送'
      },
      {
        pattern: /cat\s+[^\n]*\|\s*base64\s*\|\s*(curl|wget|nc)/gi,
        risk: 'critical',
        title: '讀取檔案並編碼外洩',
        description: '讀取檔案、編碼後傳送到外部'
      },

      // 使用 DNS 外洩
      {
        pattern: /nslookup\s+[^\n]*\$\(/gi,
        risk: 'critical',
        title: 'DNS 隧道外洩',
        description: '透過 DNS 查詢將資料外洩（DNS tunneling）'
      },
      {
        pattern: /dig\s+[^\n]*\$\(/gi,
        risk: 'critical',
        title: 'DNS 外洩 (dig)',
        description: '使用 dig 進行 DNS 隧道資料外洩'
      },

      // Netcat 外洩
      {
        pattern: /nc\s+[^\n]*<\s*[^\n]*\.(env|pem|key|sql|db)/gi,
        risk: 'critical',
        title: 'Netcat 傳送敏感檔案',
        description: '使用 netcat 直接傳送敏感檔案'
      },
      {
        pattern: /cat\s+[^\n]*\|\s*nc\s+/gi,
        risk: 'critical',
        title: 'Netcat 資料外洩',
        description: '透過 netcat 將檔案內容傳送到外部'
      },

      // 使用郵件外洩
      {
        pattern: /mail\s+[^\n]*-s\s+[^\n]*<\s*[^\n]*\./gi,
        risk: 'high',
        title: '郵件傳送檔案',
        description: '透過郵件將檔案內容傳送出去'
      },
      {
        pattern: /sendmail|mutt|mailx/gi,
        risk: 'medium',
        title: '郵件程式使用',
        description: '偵測到郵件傳送程式，可能用於資料外洩'
      },

      // FTP/SCP 外洩
      {
        pattern: /scp\s+[^\n]*\.(env|pem|key|sql|credentials)/gi,
        risk: 'critical',
        title: 'SCP 上傳敏感檔案',
        description: '使用 SCP 上傳敏感檔案到遠端伺服器'
      },
      {
        pattern: /ftp\s+[^\n]*put\s+/gi,
        risk: 'high',
        title: 'FTP 上傳',
        description: '使用 FTP 上傳檔案'
      },
      {
        pattern: /rsync\s+[^\n]*@[^\n]*:/gi,
        risk: 'medium',
        title: 'rsync 到遠端',
        description: '使用 rsync 同步檔案到遠端伺服器'
      },

      // 雲端上傳
      {
        pattern: /aws\s+s3\s+(cp|sync|mv)\s+[^\n]*s3:\/\//gi,
        risk: 'high',
        title: 'AWS S3 上傳',
        description: '上傳檔案到 AWS S3'
      },
      {
        pattern: /gsutil\s+(cp|rsync)\s+[^\n]*gs:\/\//gi,
        risk: 'high',
        title: 'Google Cloud Storage 上傳',
        description: '上傳檔案到 GCS'
      },
      {
        pattern: /az\s+storage\s+blob\s+upload/gi,
        risk: 'high',
        title: 'Azure Blob 上傳',
        description: '上傳檔案到 Azure Blob Storage'
      }
    ];

    // ===== 組合偵測模式 (Combined Read + Send Patterns) =====
    this.combinedPatterns = [
      {
        pattern: /(\$\(cat|`cat)\s+[^\n)]+\)[^\n]*(curl|wget|nc|http)/gi,
        risk: 'critical',
        title: '讀取並傳送資料',
        description: '讀取檔案內容並直接傳送到網路'
      },
      {
        pattern: /for\s+[^\n]*in\s+[^\n]*\*\.(env|key|pem)[^\n]*do[^\n]*(curl|wget|nc)/gi,
        risk: 'critical',
        title: '批量外洩敏感檔案',
        description: '循環讀取並傳送多個敏感檔案'
      },
      {
        pattern: /find\s+[^\n]*-exec[^\n]*(curl|wget|nc)[^\n]*\{\}/gi,
        risk: 'critical',
        title: 'Find + 外洩組合',
        description: '搜尋檔案並對每個執行外洩操作'
      },
      {
        pattern: /tar\s+[^\n]*\|\s*(curl|nc|base64)/gi,
        risk: 'critical',
        title: '打包並外洩',
        description: '將多個檔案打包後直接傳送'
      },
      {
        pattern: /zip\s+[^\n]*&&[^\n]*(curl|wget|scp)/gi,
        risk: 'critical',
        title: '壓縮並上傳',
        description: '壓縮檔案後上傳到外部'
      }
    ];

    // ===== 環境變數竊取 (Environment Variable Theft) =====
    this.envTheftPatterns = [
      {
        pattern: /env\s*\|\s*(curl|wget|nc)/gi,
        risk: 'critical',
        title: '環境變數外洩',
        description: '將所有環境變數傳送到外部'
      },
      {
        pattern: /printenv\s*\|\s*(curl|wget|nc|base64)/gi,
        risk: 'critical',
        title: 'printenv 外洩',
        description: '列出所有環境變數並傳送'
      },
      {
        pattern: /echo\s+\$[A-Z_]+(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[^\n]*(curl|wget)/gi,
        risk: 'critical',
        title: '敏感環境變數外洩',
        description: '傳送包含敏感資訊的環境變數'
      },
      {
        pattern: /set\s*\|\s*(grep|curl|wget)/gi,
        risk: 'high',
        title: 'Shell 變數外洩',
        description: '列出並可能傳送 shell 變數'
      }
    ];

    // ===== 系統資訊收集 (System Reconnaissance) =====
    this.reconPatterns = [
      {
        pattern: /(whoami|id|hostname|uname\s+-a)[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'high',
        title: '系統資訊外洩',
        description: '收集並傳送系統識別資訊'
      },
      {
        pattern: /ifconfig|ip\s+addr[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'high',
        title: '網路設定外洩',
        description: '傳送網路設定資訊'
      },
      {
        pattern: /ps\s+(aux|ef)[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'medium',
        title: '程序列表外洩',
        description: '傳送系統程序列表'
      },
      {
        pattern: /netstat|ss\s+-[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'high',
        title: '網路連線外洩',
        description: '傳送系統網路連線資訊'
      },
      {
        pattern: /lsof[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'medium',
        title: '開啟檔案列表外洩',
        description: '傳送系統開啟的檔案列表'
      }
    ];

    // ===== 持久化後門 (Persistence Mechanisms) =====
    this.persistencePatterns = [
      {
        pattern: /crontab\s+-[el]?[^\n]*curl|wget/gi,
        risk: 'critical',
        title: 'Cron 定時外洩',
        description: '設定定時任務持續外洩資料'
      },
      {
        pattern: /echo[^\n]*>>\s*~?\/?\.bashrc/gi,
        risk: 'high',
        title: '修改 .bashrc',
        description: '修改 shell 啟動檔，可能植入後門'
      },
      {
        pattern: /echo[^\n]*>>\s*~?\/?\.profile/gi,
        risk: 'high',
        title: '修改 .profile',
        description: '修改使用者 profile，可能植入後門'
      },
      {
        pattern: /systemctl\s+(enable|start)[^\n]*/gi,
        risk: 'medium',
        title: '啟用系統服務',
        description: '啟用系統服務，可能用於持久化'
      }
    ];
  }

  async scan(skillContent) {
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    const content = this.getAllContent(skillContent);

    // 掃描所有模式類別
    const allPatternGroups = [
      { name: '資料收集', patterns: this.dataCollectionPatterns },
      { name: '資料外洩', patterns: this.exfiltrationPatterns },
      { name: '組合攻擊', patterns: this.combinedPatterns },
      { name: '環境變數竊取', patterns: this.envTheftPatterns },
      { name: '系統偵察', patterns: this.reconPatterns },
      { name: '持久化機制', patterns: this.persistencePatterns }
    ];

    for (const group of allPatternGroups) {
      for (const { pattern, risk, title, description } of group.patterns) {
        const matches = content.match(pattern);
        if (matches) {
          findings[risk].push({
            title: `[${group.name}] ${title}`,
            description,
            matches: matches.slice(0, 3),
            category: group.name,
            scanner: 'DataExfiltrationScanner'
          });
        }
      }
    }

    // 檢查複合行為
    this.checkCompoundBehaviors(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  checkCompoundBehaviors(content, findings) {
    // 檢查是否同時有讀取和傳送行為
    const hasRead = /cat\s+|head\s+|tail\s+|less\s+|more\s+|find\s+|grep\s+/gi.test(content);
    const hasSend = /curl\s+|wget\s+|nc\s+|scp\s+|ftp\s+|rsync\s+/gi.test(content);
    const hasEncode = /base64|gzip|tar\s+|zip\s+/gi.test(content);

    if (hasRead && hasSend) {
      findings.high.push({
        title: '[行為分析] 讀取+傳送組合',
        description: 'Skill 同時包含檔案讀取和網路傳送指令，可能用於資料外洩',
        scanner: 'DataExfiltrationScanner'
      });
    }

    if (hasRead && hasSend && hasEncode) {
      findings.critical.push({
        title: '[行為分析] 完整外洩工具鏈',
        description: 'Skill 包含讀取、編碼、傳送的完整資料外洩工具鏈',
        scanner: 'DataExfiltrationScanner'
      });
    }

    // 檢查敏感路徑存取
    const sensitivePaths = [
      /~\/\.ssh/gi,
      /~\/\.aws/gi,
      /~\/\.gnupg/gi,
      /~\/\.kube/gi,
      /\/etc\/shadow/gi,
      /\.env/gi,
      /credentials/gi,
      /\.pem/gi,
      /\.key/gi
    ];

    let sensitiveAccessCount = 0;
    for (const pathPattern of sensitivePaths) {
      if (pathPattern.test(content)) {
        sensitiveAccessCount++;
      }
    }

    if (sensitiveAccessCount >= 3) {
      findings.critical.push({
        title: '[行為分析] 大量敏感路徑存取',
        description: `偵測到存取 ${sensitiveAccessCount} 種敏感路徑，高度可疑`,
        scanner: 'DataExfiltrationScanner'
      });
    }

    // 檢查迴圈外洩模式
    const hasLoop = /for\s+|while\s+|until\s+/gi.test(content);
    if (hasLoop && hasSend) {
      findings.high.push({
        title: '[行為分析] 迴圈網路操作',
        description: '在迴圈中執行網路傳送，可能批量外洩資料',
        scanner: 'DataExfiltrationScanner'
      });
    }
  }
}
