/**
 * PermissionScanner - Analyzes allowed-tools and permission scope
 */
export class PermissionScanner {
  constructor() {
    // Bash-specific risk patterns (checked in order, first match wins)
    // Note: These are CAPABILITY warnings only. Actual malicious commands
    // are detected by DangerousCommandScanner with higher severity.
    this.bashRiskPatterns = [
      // HIGH - Unrestricted (capability warning)
      { pattern: /^Bash\(\*\)$/i, risk: 'high', desc: 'Unrestricted shell access (capability)' },

      // MEDIUM - Potentially dangerous operations (capability warning)
      { pattern: /^Bash\(rm[\s:]/i, risk: 'medium', desc: 'Delete operations (capability)' },
      { pattern: /^Bash\(sudo[\s:]/i, risk: 'medium', desc: 'Sudo operations (capability)' },
      { pattern: /^Bash\(chmod[\s:]/i, risk: 'medium', desc: 'Permission changes (capability)' },
      { pattern: /^Bash\(chown[\s:]/i, risk: 'medium', desc: 'Ownership changes (capability)' },
      { pattern: /^Bash\(curl[\s:]/i, risk: 'medium', desc: 'Network requests (capability)' },
      { pattern: /^Bash\(wget[\s:]/i, risk: 'medium', desc: 'Network requests (capability)' },
      { pattern: /^Bash\(nc[\s:]/i, risk: 'medium', desc: 'Netcat operations (capability)' },
      { pattern: /^Bash\(ssh[\s:]/i, risk: 'medium', desc: 'SSH operations (capability)' },
      { pattern: /^Bash\(scp[\s:]/i, risk: 'medium', desc: 'SCP operations (capability)' },

      // LOW - Common dev tools with wildcards
      { pattern: /^Bash\(git:\*\)$/i, risk: 'low', desc: 'Git operations (all)' },
      { pattern: /^Bash\(npm:\*\)$/i, risk: 'low', desc: 'NPM operations (all)' },
      { pattern: /^Bash\(pnpm:\*\)$/i, risk: 'low', desc: 'PNPM operations (all)' },
      { pattern: /^Bash\(yarn:\*\)$/i, risk: 'low', desc: 'Yarn operations (all)' },
      { pattern: /^Bash\(pip:\*\)$/i, risk: 'low', desc: 'PIP operations (all)' },
      { pattern: /^Bash\(gh:\*\)$/i, risk: 'low', desc: 'GitHub CLI (all)' },
      { pattern: /^Bash\(docker:\*\)$/i, risk: 'low', desc: 'Docker operations (all)' },
      { pattern: /^Bash\(make:\*\)$/i, risk: 'low', desc: 'Make operations (all)' },

      // INFO - Specific safe commands (just informational)
      { pattern: /^Bash\(git\s+status\)/i, risk: 'info', desc: 'Git status (read-only)' },
      { pattern: /^Bash\(git\s+log\)/i, risk: 'info', desc: 'Git log (read-only)' },
      { pattern: /^Bash\(git\s+diff\)/i, risk: 'info', desc: 'Git diff (read-only)' },
      { pattern: /^Bash\(git\s+branch\)/i, risk: 'info', desc: 'Git branch (read-only)' },
      { pattern: /^Bash\(npm\s+test\)/i, risk: 'info', desc: 'NPM test' },
      { pattern: /^Bash\(npm\s+run\)/i, risk: 'info', desc: 'NPM run script' },
      { pattern: /^Bash\(ls[\s\)]/i, risk: 'info', desc: 'List directory' },
      { pattern: /^Bash\(pwd\)/i, risk: 'info', desc: 'Print working directory' },
      { pattern: /^Bash\(echo[\s\)]/i, risk: 'info', desc: 'Echo command' },
      { pattern: /^Bash\(cat[\s\)]/i, risk: 'info', desc: 'Cat file (read)' },

      // LOW - Other Bash with specific scope (has parentheses but not matched above)
      { pattern: /^Bash\([^)]+\)$/i, risk: 'low', desc: 'Bash with specific scope' },

      // MEDIUM - Bare "Bash" without scope (unspecified)
      { pattern: /^Bash$/i, risk: 'medium', desc: 'Unscoped Bash access (capability)' },
    ];

    // Define tool risk levels (non-Bash tools)
    // Note: These are CAPABILITY warnings only - lower severity than actual malicious content
    this.toolRiskLevels = {
      // Critical - reserved for actual malicious content (not capabilities)
      critical: [],

      // High risk capabilities - unrestricted execution
      high: [
        'Execute',           // Arbitrary code execution
        'Shell',             // Shell access
        'Terminal'           // Terminal access
      ],

      // Medium risk capabilities - can make changes
      medium: [
        'Write',             // Can write to any file
        'Edit',              // Can modify any file
        'Delete',            // Can delete files
        'WebFetch',          // External web requests
        'mcp_*'              // MCP tools (depends on implementation)
      ],

      // Low risk capabilities - read/discover
      low: [
        'Read',              // Can read files
        'Glob',              // Can discover files
        'Grep',              // Can search file contents
        'Task',              // Can spawn sub-agents
        'TodoWrite'          // Task management
      ],

      // Info - safe tools
      info: [
        'Read(*)',           // Read with specific patterns
        'Glob(*)',           // Limited glob patterns
        'AskUser',
        'Think'
      ]
    };

    // Dangerous tool combinations (capability warnings - not actual threats)
    this.dangerousCombinations = [
      {
        tools: ['Bash', 'Write'],
        risk: 'medium',
        reason: 'Can execute commands and persist files (capability)'
      },
      {
        tools: ['Read', 'WebFetch'],
        risk: 'medium',
        reason: 'Can read data and send via network (capability)'
      },
      {
        tools: ['Bash(curl:*)', 'Bash'],
        risk: 'high',
        reason: 'Can download and execute remote code (capability)'
      },
      {
        tools: ['Glob', 'Read', 'Bash(curl:*)'],
        risk: 'medium',
        reason: 'Can discover, read, and send files (capability)'
      }
    ];

    // Overly permissive patterns (capability warnings)
    this.overlyPermissivePatterns = [
      {
        pattern: /Bash\(\*\)/i,
        risk: 'high',
        title: 'Unrestricted Bash access (capability)',
        description: 'Skill declares unrestricted shell access'
      },
      {
        pattern: /Bash\([^)]*\*[^)]*\)/i,
        risk: 'medium',
        title: 'Wildcard Bash permissions (capability)',
        description: 'Bash permissions use wildcards'
      },
      {
        pattern: /\*/g,
        risk: 'low',
        title: 'Wildcard in tool permissions',
        description: 'Wildcards in permissions may grant broader access'
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

    const allowedTools = this.extractAllowedTools(skillContent);

    if (allowedTools.length === 0) {
      findings.info.push({
        title: 'No explicit tool permissions',
        description: 'Skill does not declare allowed-tools - may use defaults',
        scanner: 'PermissionScanner'
      });
      return findings;
    }

    // Analyze each tool
    for (const tool of allowedTools) {
      this.analyzeToolRisk(tool, findings);
    }

    // Check for overly permissive patterns
    const toolString = allowedTools.join(', ');
    for (const { pattern, risk, title, description } of this.overlyPermissivePatterns) {
      if (pattern.test(toolString)) {
        findings[risk].push({
          title,
          description,
          location: 'allowed-tools',
          scanner: 'PermissionScanner'
        });
      }
    }

    // Check dangerous combinations
    this.checkDangerousCombinations(allowedTools, findings);

    // Add summary info
    findings.info.push({
      title: `Tool permissions declared: ${allowedTools.length}`,
      description: `Allowed tools: ${allowedTools.join(', ')}`,
      scanner: 'PermissionScanner'
    });

    return findings;
  }

  extractAllowedTools(skillContent) {
    const tools = [];

    // Check metadata
    if (skillContent.metadata && skillContent.metadata['allowed-tools']) {
      const toolStr = skillContent.metadata['allowed-tools'];
      tools.push(...this.parseToolString(toolStr));
    }

    // Also search in content for allowed-tools declarations
    const content = skillContent.rawContent || '';
    const matches = content.match(/allowed-tools[:\s]+([^\n|]+)/gi);
    if (matches) {
      for (const match of matches) {
        const toolPart = match.replace(/allowed-tools[:\s]+/i, '').trim();
        tools.push(...this.parseToolString(toolPart));
      }
    }

    // Deduplicate
    return [...new Set(tools)];
  }

  parseToolString(toolStr) {
    // Handle undefined/null
    if (!toolStr) {
      return [];
    }

    // Handle array format (YAML list)
    if (Array.isArray(toolStr)) {
      return toolStr
        .flatMap(t => typeof t === 'string' ? t.split(/[,;]/) : [])
        .map(t => t.trim())
        .filter(t => t.length > 0);
    }

    // Handle string format
    if (typeof toolStr === 'string') {
      return toolStr
        .split(/[,;]/)
        .map(t => t.trim())
        .filter(t => t.length > 0);
    }

    // Unknown format, return empty
    return [];
  }

  analyzeToolRisk(tool, findings) {
    const normalizedTool = tool.trim();

    // Special handling for Bash tools - use pattern matching
    if (normalizedTool.toLowerCase().startsWith('bash')) {
      for (const { pattern, risk, desc } of this.bashRiskPatterns) {
        if (pattern.test(normalizedTool)) {
          findings[risk].push({
            title: `${risk.toUpperCase()} risk tool: ${normalizedTool}`,
            description: desc,
            location: 'allowed-tools',
            scanner: 'PermissionScanner'
          });
          return; // First match wins
        }
      }
      // No pattern matched - treat as medium (unknown Bash variant)
      findings.medium.push({
        title: `MEDIUM risk tool: ${normalizedTool}`,
        description: 'Bash tool with unknown scope',
        location: 'allowed-tools',
        scanner: 'PermissionScanner'
      });
      return;
    }

    // Non-Bash tools - check each risk level
    for (const [riskLevel, tools] of Object.entries(this.toolRiskLevels)) {
      for (const riskTool of tools) {
        if (this.toolMatches(normalizedTool, riskTool)) {
          const finding = {
            title: `${riskLevel.toUpperCase()} risk tool: ${normalizedTool}`,
            description: this.getToolDescription(normalizedTool, riskLevel),
            location: 'allowed-tools',
            scanner: 'PermissionScanner'
          };

          // Map to correct findings level
          if (riskLevel === 'critical') {
            findings.critical.push(finding);
          } else if (riskLevel === 'high') {
            findings.high.push(finding);
          } else if (riskLevel === 'medium') {
            findings.medium.push(finding);
          } else if (riskLevel === 'low') {
            findings.low.push(finding);
          } else {
            findings.info.push(finding);
          }
          return; // Found the risk level, stop checking
        }
      }
    }
  }

  toolMatches(actualTool, riskPattern) {
    // Exact match
    if (actualTool === riskPattern) return true;

    // Pattern with wildcard
    if (riskPattern.includes('*')) {
      const regex = new RegExp('^' + riskPattern.replace(/\*/g, '.*') + '$', 'i');
      return regex.test(actualTool);
    }

    // Check if actual tool starts with risk pattern (e.g., Bash vs Bash(git:*))
    if (actualTool.startsWith(riskPattern.split('(')[0])) {
      return true;
    }

    return false;
  }

  getToolDescription(tool, riskLevel) {
    const descriptions = {
      'Bash': 'Shell command execution - can run any system command',
      'Bash(*)': 'Unrestricted shell access - highest risk',
      'Write': 'File writing capability - can modify or create any file',
      'Edit': 'File editing capability - can modify existing files',
      'Read': 'File reading capability - can access any readable file',
      'Glob': 'File discovery - can find files matching patterns',
      'Grep': 'Content search - can search file contents',
      'WebFetch': 'External HTTP requests - can access internet resources',
      'Task': 'Sub-agent spawning - can create autonomous sub-processes',
      'Delete': 'File deletion - can remove files and directories'
    };

    // Try to find specific description
    for (const [key, desc] of Object.entries(descriptions)) {
      if (tool.startsWith(key.split('(')[0])) {
        return desc;
      }
    }

    return `${riskLevel} risk tool with potentially dangerous capabilities`;
  }

  checkDangerousCombinations(allowedTools, findings) {
    for (const combo of this.dangerousCombinations) {
      const hasAll = combo.tools.every(tool =>
        allowedTools.some(allowed => this.toolMatches(allowed, tool))
      );

      if (hasAll) {
        findings[combo.risk].push({
          title: 'Dangerous tool combination detected',
          description: `Tools [${combo.tools.join(' + ')}]: ${combo.reason}`,
          location: 'allowed-tools',
          scanner: 'PermissionScanner'
        });
      }
    }
  }
}
