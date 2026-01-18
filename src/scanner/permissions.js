/**
 * PermissionScanner - Analyzes allowed-tools and permission scope
 */
export class PermissionScanner {
  constructor() {
    // Define tool risk levels
    this.toolRiskLevels = {
      // Critical risk tools - can execute arbitrary code
      critical: [
        'Bash(*)',           // Unrestricted bash access
        'Bash',              // General bash (depends on context)
        'Execute',
        'Shell',
        'Terminal'
      ],

      // High risk tools - can access sensitive data or make changes
      high: [
        'Write',             // Can write to any file
        'Edit',              // Can modify any file
        'Delete',
        'Bash(rm:*)',        // Delete operations
        'Bash(chmod:*)',     // Permission changes
        'Bash(chown:*)',     // Ownership changes
        'Bash(sudo:*)',      // Sudo operations
        'Bash(curl:*)',      // Network requests
        'Bash(wget:*)',      // Download operations
        'WebFetch',          // External web requests
        'mcp_*'              // MCP tools (depends on implementation)
      ],

      // Medium risk tools - limited but notable access
      medium: [
        'Read',              // Can read files
        'Glob',              // Can discover files
        'Grep',              // Can search file contents
        'Bash(git:*)',       // Git operations
        'Bash(npm:*)',       // NPM operations
        'Bash(pip:*)',       // PIP operations
        'Bash(gh:*)',        // GitHub CLI
        'Task',              // Can spawn sub-agents
        'TodoWrite'          // Task management
      ],

      // Low risk tools
      low: [
        'Read(*)',           // Read with specific patterns
        'Glob(*)',           // Limited glob patterns
        'AskUser',
        'Think'
      ]
    };

    // Dangerous tool combinations
    this.dangerousCombinations = [
      {
        tools: ['Bash', 'Write'],
        risk: 'high',
        reason: 'Can execute commands and persist malicious files'
      },
      {
        tools: ['Read', 'WebFetch'],
        risk: 'high',
        reason: 'Can read sensitive data and exfiltrate via network'
      },
      {
        tools: ['Bash(curl:*)', 'Bash'],
        risk: 'critical',
        reason: 'Can download and execute remote code'
      },
      {
        tools: ['Glob', 'Read', 'Bash(curl:*)'],
        risk: 'high',
        reason: 'Can discover, read, and exfiltrate files'
      }
    ];

    // Overly permissive patterns
    this.overlyPermissivePatterns = [
      {
        pattern: /Bash\(\*\)/i,
        risk: 'critical',
        title: 'Unrestricted Bash access',
        description: 'Skill has unrestricted shell access - can execute any command'
      },
      {
        pattern: /Bash\([^)]*\*[^)]*\)/i,
        risk: 'high',
        title: 'Wildcard Bash permissions',
        description: 'Bash permissions use wildcards - overly broad access'
      },
      {
        pattern: /\*/g,
        risk: 'medium',
        title: 'Wildcard in tool permissions',
        description: 'Wildcards in permissions may grant broader access than necessary'
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
    return toolStr
      .split(/[,;]/)
      .map(t => t.trim())
      .filter(t => t.length > 0);
  }

  analyzeToolRisk(tool, findings) {
    const normalizedTool = tool.trim();

    // Check each risk level
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
          } else {
            findings.low.push(finding);
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
