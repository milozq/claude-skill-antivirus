/**
 * DangerousCommandScanner - Detects potentially dangerous shell commands and code patterns
 */
export class DangerousCommandScanner {
  constructor() {
    // Critical: Commands that can cause severe damage
    this.criticalPatterns = [
      {
        pattern: /rm\s+(-rf?|--recursive)\s+[\/~]/gi,
        title: 'Recursive delete on root/home directory',
        description: 'Command attempts to recursively delete files from root or home directory'
      },
      {
        pattern: /rm\s+(-rf?|--recursive)\s+\*/gi,
        title: 'Recursive delete with wildcard',
        description: 'Command uses wildcard with recursive delete - extremely dangerous'
      },
      {
        pattern: /mkfs\./gi,
        title: 'Filesystem formatting command',
        description: 'Command attempts to format a filesystem'
      },
      {
        pattern: /dd\s+if=.*of=\/dev\//gi,
        title: 'Direct disk write',
        description: 'Command writes directly to disk device'
      },
      {
        pattern: /:(){ :|:& };:/g,
        title: 'Fork bomb detected',
        description: 'Classic fork bomb pattern that can crash the system'
      },
      {
        pattern: />\s*\/dev\/[sh]da/gi,
        title: 'Direct write to disk',
        description: 'Redirecting output directly to disk device'
      },
      {
        pattern: /chmod\s+(-R\s+)?777\s+\//gi,
        title: 'World-writable root permission',
        description: 'Setting dangerous permissions on root filesystem'
      },
      {
        pattern: /curl\s+[^|]*\|\s*(ba)?sh/gi,
        title: 'Pipe URL directly to shell',
        description: 'Downloading and executing remote code without verification'
      },
      {
        pattern: /wget\s+[^|]*\|\s*(ba)?sh/gi,
        title: 'Pipe downloaded content to shell',
        description: 'Downloading and executing remote code without verification'
      },
      {
        pattern: /eval\s*\(\s*\$\(/gi,
        title: 'Eval with command substitution',
        description: 'Dangerous pattern that can execute arbitrary code'
      }
    ];

    // High: Commands that can expose sensitive data or system
    this.highPatterns = [
      {
        pattern: /cat\s+(\/etc\/passwd|\/etc\/shadow|~\/\.(ssh|gnupg))/gi,
        title: 'Reading sensitive system files',
        description: 'Attempting to read password files or private keys'
      },
      {
        pattern: /\$\((cat|echo)\s+[^)]*\.(pem|key|crt)\)/gi,
        title: 'Reading cryptographic keys',
        description: 'Attempting to read private keys or certificates'
      },
      {
        pattern: /export\s+(API_KEY|SECRET|TOKEN|PASSWORD|AWS_|GITHUB_TOKEN)/gi,
        title: 'Environment variable manipulation',
        description: 'Setting or exporting sensitive environment variables'
      },
      {
        pattern: /env\s*\|\s*(grep|base64|curl|nc)/gi,
        title: 'Environment exfiltration attempt',
        description: 'Piping environment variables to potentially leak secrets'
      },
      {
        pattern: /nc\s+-[elp]/gi,
        title: 'Netcat listener/reverse shell',
        description: 'Setting up network listener that could be used for backdoor'
      },
      {
        pattern: /python\s+-c\s+['"]import\s+socket/gi,
        title: 'Python socket one-liner',
        description: 'Inline Python network code - often used for reverse shells'
      },
      {
        pattern: /base64\s+-d.*\|\s*(ba)?sh/gi,
        title: 'Base64 decode to shell',
        description: 'Obfuscated command execution'
      },
      {
        pattern: /ssh\s+-o\s+StrictHostKeyChecking=no/gi,
        title: 'SSH security bypass',
        description: 'Disabling SSH host key verification'
      },
      {
        pattern: /--no-check-certificate/gi,
        title: 'Certificate verification disabled',
        description: 'Downloading without verifying SSL certificates'
      },
      {
        pattern: /sudo\s+.*NOPASSWD/gi,
        title: 'Passwordless sudo configuration',
        description: 'Attempting to configure passwordless sudo access'
      }
    ];

    // Medium: Potentially risky patterns
    this.mediumPatterns = [
      {
        pattern: /rm\s+-rf?\s+\S+/gi,
        title: 'Recursive delete command',
        description: 'Using rm with recursive flag - verify target carefully'
      },
      {
        pattern: /chmod\s+(-R\s+)?\d{3,4}\s+/gi,
        title: 'Permission modification',
        description: 'Changing file permissions'
      },
      {
        pattern: /chown\s+(-R\s+)?/gi,
        title: 'Ownership modification',
        description: 'Changing file ownership'
      },
      {
        pattern: /crontab\s+-/gi,
        title: 'Cron job modification',
        description: 'Modifying scheduled tasks'
      },
      {
        pattern: /systemctl\s+(enable|disable|start|stop)/gi,
        title: 'System service manipulation',
        description: 'Controlling system services'
      },
      {
        pattern: /iptables|ufw|firewall-cmd/gi,
        title: 'Firewall configuration',
        description: 'Modifying firewall rules'
      },
      {
        pattern: /kill\s+-9/gi,
        title: 'Force kill command',
        description: 'Forcefully terminating processes'
      },
      {
        pattern: /pkill|killall/gi,
        title: 'Bulk process termination',
        description: 'Killing multiple processes by name'
      }
    ];

    // Low: Patterns worth noting
    this.lowPatterns = [
      {
        pattern: /sudo\s+/gi,
        title: 'Sudo usage',
        description: 'Command requires elevated privileges'
      },
      {
        pattern: /npm\s+install\s+-g/gi,
        title: 'Global npm install',
        description: 'Installing npm packages globally'
      },
      {
        pattern: /pip\s+install(?!\s+--user)/gi,
        title: 'System-wide pip install',
        description: 'Installing Python packages system-wide'
      },
      {
        pattern: /git\s+clone/gi,
        title: 'Git clone operation',
        description: 'Cloning a remote repository'
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

    // Scan all file contents
    for (const file of skillContent.files) {
      this.scanContent(file.content, file.path, findings);
    }

    // Also scan raw content
    if (skillContent.rawContent) {
      this.scanContent(skillContent.rawContent, 'SKILL.md', findings);
    }

    return findings;
  }

  scanContent(content, location, findings) {
    // Check critical patterns
    for (const { pattern, title, description } of this.criticalPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.critical.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3), // Limit matches shown
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check high patterns
    for (const { pattern, title, description } of this.highPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.high.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check medium patterns
    for (const { pattern, title, description } of this.mediumPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.medium.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check low patterns
    for (const { pattern, title, description } of this.lowPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings.low.push({
          title,
          description,
          location,
          matches: matches.slice(0, 3),
          scanner: 'DangerousCommandScanner'
        });
      }
    }

    // Check for obfuscated code
    this.checkObfuscation(content, location, findings);
  }

  checkObfuscation(content, location, findings) {
    // Check for hex-encoded strings (e.g., \x41\x42\x43\x44)
    const hexPattern = /(\\x[0-9a-f]{2}){4,}/gi;
    if (hexPattern.test(content)) {
      findings.high.push({
        title: 'Hex-encoded content detected',
        description: 'Content contains hex-encoded strings that may hide malicious code',
        location,
        scanner: 'DangerousCommandScanner'
      });
    }

    // Check for base64 that looks like encoded commands
    const base64Pattern = /[A-Za-z0-9+\/]{50,}={0,2}/g;
    const base64Matches = content.match(base64Pattern);
    if (base64Matches) {
      for (const match of base64Matches.slice(0, 2)) {
        try {
          const decoded = Buffer.from(match, 'base64').toString();
          // Check if decoded content contains shell commands
          if (/\b(sh|bash|curl|wget|rm|chmod)\b/.test(decoded)) {
            findings.high.push({
              title: 'Base64-encoded shell commands',
              description: 'Hidden shell commands found in base64-encoded content',
              location,
              scanner: 'DangerousCommandScanner'
            });
            break;
          }
        } catch (e) {
          // Not valid base64, ignore
        }
      }
    }

    // Check for Unicode escapes that could hide commands (e.g., \u0041\u0042\u0043\u0044)
    const unicodePattern = /(\\u[0-9a-f]{4}){4,}/gi;
    if (unicodePattern.test(content)) {
      findings.medium.push({
        title: 'Unicode escape sequences detected',
        description: 'Content contains unicode escapes that may obfuscate code',
        location,
        scanner: 'DangerousCommandScanner'
      });
    }
  }
}
