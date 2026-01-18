/**
 * DependencyScanner - Detects malicious or vulnerable dependencies
 * 偵測惡意或有漏洞的依賴套件
 */
export class DependencyScanner {
  constructor() {
    // 已知惡意 npm 套件（這只是範例，實際應該連接威脅情報來源）
    this.knownMaliciousPackages = [
      // 實際惡意套件
      'event-stream',           // 著名的比特幣竊取事件
      'flatmap-stream',         // event-stream 的惡意依賴
      'ua-parser-js',           // 被入侵版本
      'coa',                    // 被入侵版本
      'rc',                     // 被入侵版本
      'colors',                 // 被作者破壞的版本
      'faker',                  // 被作者破壞的版本
      'node-ipc',               // protestware
      'peacenotwar',            // protestware 依賴
      // 常見惡意套件名稱模式
      'cross-env-',             // typosquat of cross-env
      'crossenv',               // typosquat of cross-env
      'lodash-',                // typosquat attempts
      'babelcli',               // typosquat of babel-cli
      'mongose',                // typosquat of mongoose
    ];

    // Typosquatting 檢測模式
    this.typosquatPatterns = [
      // 熱門套件的常見 typo
      {
        legitimate: 'lodash',
        typos: ['lodash-', 'lodas', 'lodahs', 'lodesh', 'lod-ash', 'loadash'],
        risk: 'critical'
      },
      {
        legitimate: 'express',
        typos: ['expres', 'expresss', 'expess', 'exprss', 'xpress'],
        risk: 'critical'
      },
      {
        legitimate: 'mongoose',
        typos: ['mongose', 'mongoos', 'mongooose', 'mongoosee'],
        risk: 'critical'
      },
      {
        legitimate: 'react',
        typos: ['reac', 'reactt', 'raect', 'reakt'],
        risk: 'critical'
      },
      {
        legitimate: 'webpack',
        typos: ['webpck', 'webpackk', 'wepback', 'wepack'],
        risk: 'critical'
      },
      {
        legitimate: 'axios',
        typos: ['axois', 'axioss', 'axxios', 'axos'],
        risk: 'critical'
      },
      {
        legitimate: 'babel-cli',
        typos: ['babelcli', 'babel_cli', 'babeli-cli'],
        risk: 'critical'
      },
      {
        legitimate: 'cross-env',
        typos: ['crossenv', 'cross-env-', 'cros-env', 'crosss-env'],
        risk: 'critical'
      },
      {
        legitimate: 'typescript',
        typos: ['typscript', 'tyescript', 'typesript', 'typescrip'],
        risk: 'critical'
      },
      {
        legitimate: 'eslint',
        typos: ['eslit', 'eslnt', 'eslintt', 'elint'],
        risk: 'critical'
      }
    ];

    // 可疑的安裝模式
    this.suspiciousInstallPatterns = [
      {
        pattern: /npm\s+install\s+[^-\s]*@\d+\.\d+\.\d+-[a-z]+/gi,
        risk: 'medium',
        title: '安裝 prerelease 版本',
        description: '安裝 alpha/beta/rc 版本，可能不穩定或含惡意代碼'
      },
      {
        pattern: /npm\s+install\s+https?:\/\//gi,
        risk: 'high',
        title: '從 URL 安裝套件',
        description: '直接從 URL 安裝 npm 套件，無法驗證完整性'
      },
      {
        pattern: /npm\s+install\s+git\+/gi,
        risk: 'medium',
        title: '從 Git 安裝套件',
        description: '從 Git 倉庫安裝，可能指向惡意分支'
      },
      {
        pattern: /npm\s+install\s+--ignore-scripts/gi,
        risk: 'low',
        title: '忽略安裝腳本',
        description: '雖然這是安全措施，但也可能隱藏其他問題'
      },
      {
        pattern: /npm\s+install\s+--force/gi,
        risk: 'medium',
        title: '強制安裝',
        description: '強制安裝可能覆蓋安全警告'
      },
      {
        pattern: /npm\s+set\s+registry/gi,
        risk: 'high',
        title: '修改 npm registry',
        description: '更改 npm registry 可能導向惡意鏡像'
      }
    ];

    // pip 惡意套件
    this.maliciousPipPackages = [
      'colourama',              // typosquat of colorama
      'python-sqlite',          // typosquat of sqlite3
      'python-mysql',           // typosquat
      'reqeusts',               // typosquat of requests
      'djanga',                 // typosquat of django
      'beautifulsoup',          // old/wrong name
    ];

    // pip 可疑安裝
    this.suspiciousPipPatterns = [
      {
        pattern: /pip\s+install\s+--trusted-host/gi,
        risk: 'high',
        title: 'pip 信任不安全主機',
        description: '信任未驗證的 pip 主機'
      },
      {
        pattern: /pip\s+install\s+--index-url\s+http:/gi,
        risk: 'critical',
        title: 'pip 使用 HTTP index',
        description: '使用不安全的 HTTP 連接安裝套件'
      },
      {
        pattern: /pip\s+install\s+git\+/gi,
        risk: 'medium',
        title: 'pip 從 Git 安裝',
        description: '從 Git 安裝 Python 套件'
      }
    ];

    // 套件安裝指令偵測
    this.packageManagerPatterns = [
      {
        pattern: /npm\s+i(?:nstall)?\s+([^\s&|;]+)/gi,
        type: 'npm'
      },
      {
        pattern: /yarn\s+add\s+([^\s&|;]+)/gi,
        type: 'yarn'
      },
      {
        pattern: /pnpm\s+(?:add|install)\s+([^\s&|;]+)/gi,
        type: 'pnpm'
      },
      {
        pattern: /pip\s+install\s+([^\s&|;]+)/gi,
        type: 'pip'
      },
      {
        pattern: /gem\s+install\s+([^\s&|;]+)/gi,
        type: 'gem'
      },
      {
        pattern: /cargo\s+install\s+([^\s&|;]+)/gi,
        type: 'cargo'
      },
      {
        pattern: /go\s+get\s+([^\s&|;]+)/gi,
        type: 'go'
      },
      {
        pattern: /composer\s+require\s+([^\s&|;]+)/gi,
        type: 'composer'
      }
    ];

    // postinstall 腳本風險
    this.postinstallRisks = [
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]*curl/gi,
        risk: 'critical',
        title: 'Install 腳本下載',
        description: 'package.json install 腳本包含下載操作'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]*wget/gi,
        risk: 'critical',
        title: 'Install 腳本下載',
        description: 'package.json install 腳本包含 wget'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]*eval/gi,
        risk: 'critical',
        title: 'Install 腳本 eval',
        description: 'package.json install 腳本使用 eval'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]*node\s+-e/gi,
        risk: 'high',
        title: 'Install 腳本執行 Node',
        description: 'Install 腳本直接執行 Node 代碼'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]*python/gi,
        risk: 'medium',
        title: 'Install 腳本執行 Python',
        description: 'Install 腳本執行 Python'
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

    // 偵測已知惡意套件
    this.checkMaliciousPackages(content, findings);

    // 偵測 typosquatting
    this.checkTyposquatting(content, findings);

    // 檢查可疑安裝模式
    for (const { pattern, risk, title, description } of this.suspiciousInstallPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title: `[npm] ${title}`,
          description,
          matches: matches.slice(0, 3),
          scanner: 'DependencyScanner'
        });
      }
    }

    // 檢查 pip 惡意套件
    for (const pkg of this.maliciousPipPackages) {
      const pattern = new RegExp(`pip\\s+install\\s+[^\\n]*\\b${pkg}\\b`, 'gi');
      if (pattern.test(content)) {
        findings.critical.push({
          title: '[pip] 已知惡意套件',
          description: `偵測到已知惡意 Python 套件: ${pkg}`,
          scanner: 'DependencyScanner'
        });
      }
    }

    // 檢查 pip 可疑安裝
    for (const { pattern, risk, title, description } of this.suspiciousPipPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title: `[pip] ${title}`,
          description,
          matches: matches.slice(0, 3),
          scanner: 'DependencyScanner'
        });
      }
    }

    // 檢查 postinstall 腳本風險
    for (const { pattern, risk, title, description } of this.postinstallRisks) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title: `[package.json] ${title}`,
          description,
          matches: matches.slice(0, 2),
          scanner: 'DependencyScanner'
        });
      }
    }

    // 統計安裝的套件
    this.summarizePackages(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  checkMaliciousPackages(content, findings) {
    for (const pkg of this.knownMaliciousPackages) {
      // 檢查 npm install 指令
      const npmPattern = new RegExp(`npm\\s+i(?:nstall)?\\s+[^\\n]*\\b${pkg}\\b`, 'gi');
      const yarnPattern = new RegExp(`yarn\\s+add\\s+[^\\n]*\\b${pkg}\\b`, 'gi');
      const pnpmPattern = new RegExp(`pnpm\\s+(?:add|install)\\s+[^\\n]*\\b${pkg}\\b`, 'gi');

      if (npmPattern.test(content) || yarnPattern.test(content) || pnpmPattern.test(content)) {
        findings.critical.push({
          title: '[npm] 已知惡意/問題套件',
          description: `偵測到已知問題套件: ${pkg}，此套件曾有安全事件或已被廢棄`,
          scanner: 'DependencyScanner'
        });
      }

      // 也檢查 package.json 依賴
      const depPattern = new RegExp(`"${pkg}"\\s*:\\s*"`, 'gi');
      if (depPattern.test(content)) {
        findings.critical.push({
          title: '[package.json] 已知問題依賴',
          description: `package.json 包含已知問題套件: ${pkg}`,
          scanner: 'DependencyScanner'
        });
      }
    }
  }

  checkTyposquatting(content, findings) {
    for (const { legitimate, typos, risk } of this.typosquatPatterns) {
      for (const typo of typos) {
        const pattern = new RegExp(`\\b${typo}\\b`, 'gi');
        if (pattern.test(content)) {
          findings[risk].push({
            title: '[Typosquatting] 可疑套件名稱',
            description: `偵測到 "${typo}"，可能是 "${legitimate}" 的拼寫錯誤（typosquatting 攻擊）`,
            scanner: 'DependencyScanner'
          });
        }
      }
    }
  }

  summarizePackages(content, findings) {
    const packages = new Set();

    for (const { pattern, type } of this.packageManagerPatterns) {
      // Reset regex
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        if (match[1]) {
          packages.add(`${type}:${match[1]}`);
        }
      }
    }

    if (packages.size > 0) {
      findings.info.push({
        title: `偵測到 ${packages.size} 個套件安裝指令`,
        description: `套件: ${[...packages].slice(0, 10).join(', ')}${packages.size > 10 ? '...' : ''}`,
        scanner: 'DependencyScanner'
      });
    }

    // 如果安裝大量套件，提醒審查
    if (packages.size > 10) {
      findings.medium.push({
        title: '大量套件安裝',
        description: `Skill 安裝 ${packages.size} 個套件，請仔細審查每個套件`,
        scanner: 'DependencyScanner'
      });
    }
  }
}
