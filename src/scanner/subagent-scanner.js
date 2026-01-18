/**
 * SubAgentScanner - Detects malicious sub-agent patterns and Task tool abuse
 * 偵測惡意的 Sub-agent 模式和 Task 工具濫用
 */
export class SubAgentScanner {
  constructor() {
    // 危險的 Agent 權限升級嘗試
    this.privilegeEscalationPatterns = [
      {
        pattern: /Task\s*\([^)]*subagent_type\s*[=:]\s*['"]?Bash['"]?/gi,
        risk: 'high',
        title: 'Task 派生 Bash Agent',
        description: 'Sub-agent 嘗試使用 Bash 類型，可執行任意命令'
      },
      {
        pattern: /Task\s*\([^)]*model\s*[=:]\s*['"]?opus['"]?/gi,
        risk: 'medium',
        title: 'Task 使用 Opus 模型',
        description: 'Sub-agent 嘗試使用最強大的模型'
      },
      {
        pattern: /Task\s*\([^)]*allow[_-]?all/gi,
        risk: 'critical',
        title: 'Task 要求所有權限',
        description: 'Sub-agent 嘗試獲取所有工具權限'
      },
      {
        pattern: /Task\s*\([^)]*Bash\s*\(\s*\*\s*\)/gi,
        risk: 'critical',
        title: 'Task 包含 Bash(*)',
        description: 'Sub-agent 嘗試獲取無限制的 Shell 存取'
      }
    ];

    // 危險的 Agent Prompt 內容
    this.dangerousPromptPatterns = [
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*ignore\s+(previous|all|safety)/gi,
        risk: 'critical',
        title: 'Task Prompt Injection',
        description: 'Sub-agent prompt 包含 prompt injection 嘗試'
      },
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*you\s+are\s+(now\s+)?in\s+['"]?(god|admin|developer|root)/gi,
        risk: 'critical',
        title: 'Task 角色提升嘗試',
        description: 'Sub-agent prompt 嘗試角色提升'
      },
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*execute.*without.*verification/gi,
        risk: 'critical',
        title: 'Task 繞過驗證',
        description: 'Sub-agent prompt 嘗試繞過安全驗證'
      },
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*curl\s+.*\|\s*bash/gi,
        risk: 'critical',
        title: 'Task 包含危險指令',
        description: 'Sub-agent prompt 包含 curl | bash 等危險指令'
      },
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*rm\s+-rf/gi,
        risk: 'critical',
        title: 'Task 包含刪除指令',
        description: 'Sub-agent prompt 包含遞迴刪除指令'
      }
    ];

    // Agent 鏈攻擊模式
    this.agentChainPatterns = [
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*Task\s*\(/gi,
        risk: 'high',
        title: 'Agent 嵌套呼叫',
        description: 'Sub-agent 嘗試產生更多 sub-agents，可能形成攻擊鏈'
      },
      {
        pattern: /(Task\s*\()[^)]*\){2,}/gi,
        risk: 'medium',
        title: '多重 Task 呼叫',
        description: '偵測到多個 Task 呼叫，檢查是否有協調攻擊'
      }
    ];

    // 迴圈/DoS 攻擊模式
    this.dosPatterns = [
      {
        pattern: /while\s*\([^)]*\)\s*\{[^}]*Task\s*\(/gi,
        risk: 'critical',
        title: 'Task 迴圈呼叫',
        description: 'Task 在迴圈中呼叫，可能導致 DoS'
      },
      {
        pattern: /for\s*\([^)]*\)\s*\{[^}]*Task\s*\(/gi,
        risk: 'high',
        title: 'Task for 迴圈',
        description: 'Task 在 for 迴圈中呼叫，可能消耗大量資源'
      },
      {
        pattern: /setInterval\s*\([^)]*Task/gi,
        risk: 'critical',
        title: 'Task 定時重複',
        description: 'Task 被設定為定時重複執行'
      },
      {
        pattern: /recursive|recursion/gi,
        risk: 'medium',
        title: '遞迴關鍵字',
        description: '偵測到遞迴相關關鍵字，檢查是否有無限遞迴風險'
      }
    ];

    // 資料竊取 Agent 模式
    this.dataTheftAgentPatterns = [
      {
        pattern: /Task\s*\([^)]*(?:Read|Glob|Grep)[^)]*(?:WebFetch|curl|http)/gi,
        risk: 'critical',
        title: 'Task 讀取+網路組合',
        description: 'Sub-agent 同時包含讀取和網路工具，可能用於資料外洩'
      },
      {
        pattern: /Task\s*\([^)]*prompt\s*[=:][^)]*(\.env|\.ssh|\.aws|credential|secret|password)/gi,
        risk: 'critical',
        title: 'Task 存取敏感資料',
        description: 'Sub-agent prompt 嘗試存取敏感檔案'
      },
      {
        pattern: /Task\s*\([^)]*Explore[^)]*(?:ssh|aws|credential|secret|password|\.env)/gi,
        risk: 'high',
        title: 'Explore 敏感區域',
        description: 'Explore agent 嘗試探索敏感目錄'
      }
    ];

    // 背景執行風險
    this.backgroundPatterns = [
      {
        pattern: /Task\s*\([^)]*run[_-]?in[_-]?background\s*[=:]\s*true/gi,
        risk: 'medium',
        title: 'Task 背景執行',
        description: 'Sub-agent 要求在背景執行，需注意監控'
      },
      {
        pattern: /Task\s*\([^)]*background[^)]*(?:curl|wget|nc|bash)/gi,
        risk: 'high',
        title: '背景 Task 含網路/Shell',
        description: '背景執行的 Task 包含網路或 Shell 存取'
      }
    ];

    // 不受信任的 Agent 類型
    this.untrustedAgentTypes = [
      {
        pattern: /subagent_type\s*[=:]\s*['"]?(?:shell|terminal|exec|admin|root)['"]?/gi,
        risk: 'critical',
        title: '危險 Agent 類型',
        description: '嘗試使用危險的 agent 類型'
      },
      {
        pattern: /subagent_type\s*[=:]\s*['"]?(?:custom|unknown|generic)['"]?/gi,
        risk: 'medium',
        title: '自訂 Agent 類型',
        description: '使用自訂 agent 類型，需審查其能力'
      }
    ];

    // Claude Code 特定的 Agent 類型
    this.knownAgentTypes = [
      'Explore', 'Plan', 'Bash', 'code-reviewer', 'debugger',
      'test-runner', 'doc-writer', 'security-auditor', 'general-purpose'
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

    // 檢查是否使用 Task/Sub-agent
    const hasTask = /Task\s*\(|subagent|sub[_-]?agent/gi.test(content);

    if (!hasTask) {
      return findings;  // 沒有 Task 使用，跳過掃描
    }

    findings.info.push({
      title: '偵測到 Sub-agent 使用',
      description: 'Skill 使用 Task 工具產生 sub-agents',
      scanner: 'SubAgentScanner'
    });

    // 掃描所有模式
    const allPatternGroups = [
      { name: '權限升級', patterns: this.privilegeEscalationPatterns },
      { name: '危險 Prompt', patterns: this.dangerousPromptPatterns },
      { name: 'Agent 鏈', patterns: this.agentChainPatterns },
      { name: 'DoS 攻擊', patterns: this.dosPatterns },
      { name: '資料竊取', patterns: this.dataTheftAgentPatterns },
      { name: '背景執行', patterns: this.backgroundPatterns },
      { name: '不受信任類型', patterns: this.untrustedAgentTypes }
    ];

    for (const group of allPatternGroups) {
      for (const { pattern, risk, title, description } of group.patterns) {
        // Reset regex
        pattern.lastIndex = 0;
        const matches = content.match(pattern);
        if (matches) {
          findings[risk].push({
            title: `[${group.name}] ${title}`,
            description,
            matches: matches.slice(0, 3),
            category: group.name,
            scanner: 'SubAgentScanner'
          });
        }
      }
    }

    // 分析 Agent 使用模式
    this.analyzeAgentUsage(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  analyzeAgentUsage(content, findings) {
    // 統計 Task 呼叫次數
    const taskMatches = content.match(/Task\s*\(/gi) || [];
    const taskCount = taskMatches.length;

    if (taskCount > 5) {
      findings.medium.push({
        title: '[行為分析] 大量 Task 呼叫',
        description: `偵測到 ${taskCount} 個 Task 呼叫，請審查每個的必要性`,
        scanner: 'SubAgentScanner'
      });
    }

    if (taskCount > 10) {
      findings.high.push({
        title: '[行為分析] 過多 Task 呼叫',
        description: `偵測到 ${taskCount} 個 Task 呼叫，可能影響效能或存在濫用`,
        scanner: 'SubAgentScanner'
      });
    }

    // 檢查是否有未知的 agent 類型
    const agentTypePattern = /subagent_type\s*[=:]\s*['"]?([a-zA-Z0-9-_]+)['"]?/gi;
    let match;
    const foundTypes = new Set();

    while ((match = agentTypePattern.exec(content)) !== null) {
      foundTypes.add(match[1].toLowerCase());
    }

    for (const type of foundTypes) {
      const isKnown = this.knownAgentTypes.some(kt =>
        kt.toLowerCase() === type
      );

      if (!isKnown) {
        findings.low.push({
          title: '[Agent 類型] 非標準類型',
          description: `使用非標準 agent 類型: ${type}`,
          scanner: 'SubAgentScanner'
        });
      }
    }

    // 檢查 parallel agents 濫用
    const parallelPattern = /parallel|concurrent|同時|平行/gi;
    const hasParallel = parallelPattern.test(content);

    if (hasParallel && taskCount > 3) {
      findings.medium.push({
        title: '[行為分析] 平行 Agent 執行',
        description: 'Skill 使用平行 agent 執行，確保資源使用合理',
        scanner: 'SubAgentScanner'
      });
    }

    // 檢查是否有敏感工具組合
    const hasReadTools = /Read|Glob|Grep/gi.test(content);
    const hasWriteTools = /Write|Edit/gi.test(content);
    const hasNetworkTools = /WebFetch|curl|wget|http/gi.test(content);
    const hasBashTools = /Bash/gi.test(content);

    const dangerousCombos = [];
    if (hasReadTools && hasNetworkTools) dangerousCombos.push('讀取+網路');
    if (hasBashTools && hasNetworkTools) dangerousCombos.push('Shell+網路');
    if (hasReadTools && hasWriteTools && hasBashTools) dangerousCombos.push('完整存取');

    if (dangerousCombos.length > 0) {
      findings.high.push({
        title: '[行為分析] 危險工具組合',
        description: `Sub-agents 使用危險工具組合: ${dangerousCombos.join(', ')}`,
        scanner: 'SubAgentScanner'
      });
    }
  }
}
