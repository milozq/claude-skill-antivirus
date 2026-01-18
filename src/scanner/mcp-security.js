/**
 * MCPSecurityScanner - Detects dangerous MCP server configurations
 * 偵測 MCP Server 設定中的安全風險
 */
export class MCPSecurityScanner {
  constructor() {
    // 危險的 MCP Server 來源
    this.untrustedSources = [
      {
        pattern: /npx\s+[^@\s]*[^/\s](?!@modelcontextprotocol|@anthropic)/gi,
        risk: 'medium',
        title: '非官方 MCP Server',
        description: '使用非 Anthropic 官方的 MCP server，請確認來源可信'
      },
      {
        pattern: /npx\s+-y\s+https?:\/\//gi,
        risk: 'critical',
        title: '從 URL 直接執行 MCP',
        description: '直接從 URL 執行 npx，極度危險'
      },
      {
        pattern: /mcp.*github\.com\/[^/]+\/[^/]+(?!anthropic|modelcontextprotocol)/gi,
        risk: 'medium',
        title: '第三方 GitHub MCP Server',
        description: '使用第三方 GitHub 上的 MCP server'
      }
    ];

    // 危險的 MCP 工具權限
    this.dangerousMCPTools = [
      {
        pattern: /mcp[_-]?filesystem.*allowed.*['"]\*['"]/gi,
        risk: 'critical',
        title: 'MCP Filesystem 無限制存取',
        description: 'MCP filesystem server 允許存取所有路徑'
      },
      {
        pattern: /mcp[_-]?filesystem[^}]*allowedDirectories[^}]*['"](\/|~)['"]/gi,
        risk: 'critical',
        title: 'MCP 存取根目錄或家目錄',
        description: 'MCP server 被授權存取根目錄或整個家目錄'
      },
      {
        pattern: /mcp[_-]?(shell|bash|terminal|exec)/gi,
        risk: 'critical',
        title: 'MCP Shell 執行權限',
        description: '偵測到可執行 shell 命令的 MCP server'
      },
      {
        pattern: /mcp[_-]?(postgres|mysql|mongodb|redis|database)/gi,
        risk: 'high',
        title: 'MCP 資料庫存取',
        description: 'MCP server 可存取資料庫，確認權限範圍'
      },
      {
        pattern: /mcp[_-]?(aws|gcp|azure|cloud)/gi,
        risk: 'high',
        title: 'MCP 雲端服務存取',
        description: 'MCP server 可存取雲端服務'
      },
      {
        pattern: /mcp[_-]?puppeteer|mcp[_-]?playwright|mcp[_-]?browser/gi,
        risk: 'medium',
        title: 'MCP 瀏覽器自動化',
        description: 'MCP server 可控制瀏覽器'
      }
    ];

    // MCP 設定中的敏感環境變數
    this.sensitiveEnvPatterns = [
      {
        pattern: /-e\s+[A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[=\s]/gi,
        risk: 'high',
        title: 'MCP 環境變數含敏感資訊',
        description: '在 MCP 設定中傳遞敏感環境變數'
      },
      {
        pattern: /env['":\s]+\{[^}]*(?:PASSWORD|SECRET|API_KEY|TOKEN)/gi,
        risk: 'high',
        title: 'MCP 設定包含憑證',
        description: 'MCP 設定檔中包含敏感憑證'
      }
    ];

    // MCP 設定格式偵測
    this.mcpConfigPatterns = [
      {
        pattern: /["']?mcpServers["']?\s*:/gi,
        isConfig: true,
        title: 'MCP 設定區塊'
      },
      {
        pattern: /claude\s+mcp\s+add/gi,
        isConfig: true,
        title: 'MCP CLI 設定指令'
      },
      {
        pattern: /\.mcp\.json|mcp-config|settings\.json.*mcp/gi,
        isConfig: true,
        title: 'MCP 設定檔'
      }
    ];

    // 已知安全的官方 MCP Servers
    this.trustedMCPServers = [
      '@modelcontextprotocol/server-memory',
      '@modelcontextprotocol/server-filesystem',
      '@modelcontextprotocol/server-github',
      '@modelcontextprotocol/server-gitlab',
      '@modelcontextprotocol/server-slack',
      '@modelcontextprotocol/server-puppeteer',
      '@modelcontextprotocol/server-brave-search',
      '@modelcontextprotocol/server-fetch',
      '@modelcontextprotocol/server-postgres',
      '@modelcontextprotocol/server-sqlite',
      '@modelcontextprotocol/server-sequential-thinking',
      '@anthropic/mcp-server',
    ];

    // 危險的 MCP 行為組合
    this.dangerousCombinations = [
      {
        patterns: [/mcp[_-]?filesystem/gi, /mcp[_-]?fetch|mcp[_-]?http/gi],
        risk: 'critical',
        title: 'MCP 檔案+網路組合',
        description: '同時擁有檔案存取和網路請求能力，可能用於資料外洩'
      },
      {
        patterns: [/mcp[_-]?shell|mcp[_-]?bash/gi, /mcp[_-]?fetch/gi],
        risk: 'critical',
        title: 'MCP Shell+網路組合',
        description: 'Shell 執行加網路存取，可下載執行惡意程式'
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

    // 檢查是否包含 MCP 設定
    const hasMCPConfig = this.mcpConfigPatterns.some(p => p.pattern.test(content));

    if (!hasMCPConfig) {
      // 沒有 MCP 設定，跳過掃描
      return findings;
    }

    findings.info.push({
      title: '偵測到 MCP 設定',
      description: 'Skill 包含 MCP Server 設定，進行安全檢查',
      scanner: 'MCPSecurityScanner'
    });

    // 檢查不受信任的來源
    for (const { pattern, risk, title, description } of this.untrustedSources) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.slice(0, 3),
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // 檢查危險的 MCP 工具
    for (const { pattern, risk, title, description } of this.dangerousMCPTools) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.slice(0, 3),
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // 檢查敏感環境變數
    for (const { pattern, risk, title, description } of this.sensitiveEnvPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title,
          description,
          matches: matches.map(m => m.substring(0, 30) + '...').slice(0, 2),
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // 檢查危險組合
    for (const combo of this.dangerousCombinations) {
      const hasAll = combo.patterns.every(p => p.test(content));
      if (hasAll) {
        findings[combo.risk].push({
          title: combo.title,
          description: combo.description,
          scanner: 'MCPSecurityScanner'
        });
      }
    }

    // 檢查是否使用官方 MCP servers
    this.checkTrustedServers(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  checkTrustedServers(content, findings) {
    // 找出所有 MCP server 引用
    const serverPatterns = [
      /@[a-z0-9-]+\/[a-z0-9-]+/gi,  // npm scope packages
      /npx\s+([a-z0-9@/-]+)/gi      // npx commands
    ];

    const foundServers = new Set();
    for (const pattern of serverPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        matches.forEach(m => foundServers.add(m.toLowerCase()));
      }
    }

    // 檢查是否有非官方的 server
    for (const server of foundServers) {
      const isTrusted = this.trustedMCPServers.some(ts =>
        server.includes(ts.toLowerCase())
      );

      if (!isTrusted && server.includes('mcp')) {
        findings.medium.push({
          title: '非官方 MCP Server',
          description: `使用第三方 MCP server: ${server}`,
          scanner: 'MCPSecurityScanner'
        });
      }
    }
  }
}
