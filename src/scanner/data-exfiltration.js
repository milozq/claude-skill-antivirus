/**
 * DataExfiltrationScanner - Detects data theft and exfiltration patterns
 * Specifically detects malicious behavior of reading local data and sending it externally
 */
export class DataExfiltrationScanner {
  constructor() {
    // ===== Data Collection Patterns =====
    this.dataCollectionPatterns = [
      // Reading sensitive files
      {
        pattern: /cat\s+[^\n]*\.(env|pem|key|crt|p12|pfx|jks|keystore|credentials|secret)/gi,
        risk: 'critical',
        title: 'Reading sensitive credential files',
        description: 'Attempts to read environment variables, private keys or credential files'
      },
      {
        pattern: /cat\s+[^\n]*(\.ssh\/|\.gnupg\/|\.aws\/|\.kube\/|\.docker\/)/gi,
        risk: 'critical',
        title: 'Reading sensitive config directories',
        description: 'Attempts to access SSH, GPG, AWS, Kubernetes or Docker configuration'
      },
      {
        pattern: /cat\s+[^\n]*(\/etc\/shadow|\/etc\/passwd|\/etc\/sudoers)/gi,
        risk: 'critical',
        title: 'Reading system auth files',
        description: 'Attempts to read system password or permission configuration files'
      },
      {
        pattern: /find\s+[^\n]*-name\s+[^\n]*\.(pem|key|env|secret|credential)/gi,
        risk: 'high',
        title: 'Searching for sensitive files',
        description: 'Using find to search for credential or secret files'
      },
      {
        pattern: /grep\s+(-r\s+)?[^\n]*(password|secret|api.?key|token|credential)/gi,
        risk: 'high',
        title: 'Searching for passwords',
        description: 'Searching for password or key keywords in files'
      },
      {
        pattern: /ls\s+(-la?\s+)?[^\n]*(\.ssh|\.gnupg|\.aws|\.config)/gi,
        risk: 'medium',
        title: 'Listing sensitive directories',
        description: 'Listing directories that may contain credentials'
      },

      // Reading browser data
      {
        pattern: /[^\n]*(Chrome|Firefox|Safari|Edge)[^\n]*(Login\s*Data|cookies|Cookies|passwords)/gi,
        risk: 'critical',
        title: 'Accessing browser passwords/cookies',
        description: 'Attempts to read browser stored login credentials or cookies'
      },
      {
        pattern: /[^\n]*\.mozilla\/firefox\/[^\n]*\.sqlite/gi,
        risk: 'critical',
        title: 'Accessing Firefox database',
        description: 'Attempts to read Firefox SQLite database'
      },
      {
        pattern: /[^\n]*\.config\/google-chrome\/[^\n]*/gi,
        risk: 'high',
        title: 'Accessing Chrome config',
        description: 'Attempts to read Chrome browser configuration'
      },

      // Reading password managers
      {
        pattern: /[^\n]*(1password|bitwarden|lastpass|keepass|dashlane)[^\n]*/gi,
        risk: 'critical',
        title: 'Accessing password manager',
        description: 'Attempts to access password manager data'
      },

      // Reading history files
      {
        pattern: /cat\s+[^\n]*(\.bash_history|\.zsh_history|\.history|fish_history)/gi,
        risk: 'high',
        title: 'Reading shell history',
        description: 'Attempts to read command history which may contain sensitive commands'
      },

      // Reading Git credentials
      {
        pattern: /cat\s+[^\n]*\.git-credentials/gi,
        risk: 'critical',
        title: 'Reading Git credentials',
        description: 'Attempts to read Git stored authentication info'
      },
      {
        pattern: /cat\s+[^\n]*\.gitconfig/gi,
        risk: 'medium',
        title: 'Reading Git config',
        description: 'Reading Git config which may contain user info'
      },

      // Reading databases
      {
        pattern: /cat\s+[^\n]*\.(sql|sqlite|db|sqlite3)/gi,
        risk: 'high',
        title: 'Reading database files',
        description: 'Attempts to read local database files'
      },
      {
        pattern: /sqlite3\s+[^\n]*\.(db|sqlite)/gi,
        risk: 'high',
        title: 'Accessing SQLite database',
        description: 'Using sqlite3 to access local database'
      }
    ];

    // ===== Data Exfiltration Patterns =====
    this.exfiltrationPatterns = [
      // curl/wget POST data transmission
      {
        pattern: /curl\s+[^\n]*(-d|--data|--data-binary|--data-raw)\s+[^\n]*(\$\(|`|\$\{)/gi,
        risk: 'critical',
        title: 'curl sending command output',
        description: 'Using curl to send command execution results to external server'
      },
      {
        pattern: /curl\s+[^\n]*(-d|--data)\s+@/gi,
        risk: 'critical',
        title: 'curl uploading file content',
        description: 'Using curl to upload local files to external server'
      },
      {
        pattern: /curl\s+[^\n]*-F\s+[^\n]*file=@/gi,
        risk: 'critical',
        title: 'curl form file upload',
        description: 'Using curl form to upload files externally'
      },
      {
        pattern: /wget\s+[^\n]*--post-file/gi,
        risk: 'critical',
        title: 'wget file upload',
        description: 'Using wget to upload files to external server'
      },

      // Base64 encoded exfiltration
      {
        pattern: /base64\s+[^\n]*\|\s*curl/gi,
        risk: 'critical',
        title: 'Base64 encoded exfiltration',
        description: 'Sending base64 encoded data via curl'
      },
      {
        pattern: /cat\s+[^\n]*\|\s*base64\s*\|\s*(curl|wget|nc)/gi,
        risk: 'critical',
        title: 'Read, encode and exfiltrate',
        description: 'Reading files, encoding and sending externally'
      },

      // DNS exfiltration
      {
        pattern: /nslookup\s+[^\n]*\$\(/gi,
        risk: 'critical',
        title: 'DNS tunnel exfiltration',
        description: 'Exfiltrating data via DNS queries (DNS tunneling)'
      },
      {
        pattern: /dig\s+[^\n]*\$\(/gi,
        risk: 'critical',
        title: 'DNS exfil via dig',
        description: 'Using dig for DNS tunnel data exfiltration'
      },

      // Netcat exfiltration
      {
        pattern: /nc\s+[^\n]*<\s*[^\n]*\.(env|pem|key|sql|db)/gi,
        risk: 'critical',
        title: 'Netcat sending sensitive files',
        description: 'Using netcat to send sensitive files directly'
      },
      {
        pattern: /cat\s+[^\n]*\|\s*nc\s+/gi,
        risk: 'critical',
        title: 'Netcat data exfiltration',
        description: 'Sending file contents externally via netcat'
      },

      // Email exfiltration
      {
        pattern: /mail\s+[^\n]*-s\s+[^\n]*<\s*[^\n]*\./gi,
        risk: 'high',
        title: 'Email file sending',
        description: 'Sending file contents via email'
      },
      {
        pattern: /sendmail|mutt|mailx/gi,
        risk: 'medium',
        title: 'Mail program usage',
        description: 'Detected mail program, may be used for data exfiltration'
      },

      // FTP/SCP exfiltration
      {
        pattern: /scp\s+[^\n]*\.(env|pem|key|sql|credentials)/gi,
        risk: 'critical',
        title: 'SCP uploading sensitive files',
        description: 'Using SCP to upload sensitive files to remote server'
      },
      {
        pattern: /ftp\s+[^\n]*put\s+/gi,
        risk: 'high',
        title: 'FTP upload',
        description: 'Uploading files via FTP'
      },
      {
        pattern: /rsync\s+[^\n]*@[^\n]*:/gi,
        risk: 'medium',
        title: 'rsync to remote',
        description: 'Using rsync to sync files to remote server'
      },

      // Cloud upload
      {
        pattern: /aws\s+s3\s+(cp|sync|mv)\s+[^\n]*s3:\/\//gi,
        risk: 'high',
        title: 'AWS S3 upload',
        description: 'Uploading files to AWS S3'
      },
      {
        pattern: /gsutil\s+(cp|rsync)\s+[^\n]*gs:\/\//gi,
        risk: 'high',
        title: 'Google Cloud Storage upload',
        description: 'Uploading files to GCS'
      },
      {
        pattern: /az\s+storage\s+blob\s+upload/gi,
        risk: 'high',
        title: 'Azure Blob upload',
        description: 'Uploading files to Azure Blob Storage'
      }
    ];

    // ===== Combined Read + Send Patterns =====
    this.combinedPatterns = [
      {
        pattern: /(\$\(cat|`cat)\s+[^\n)]+\)[^\n]*(curl|wget|nc|http)/gi,
        risk: 'critical',
        title: 'Read and send data',
        description: 'Reading file content and sending directly to network'
      },
      {
        pattern: /for\s+[^\n]*in\s+[^\n]*\*\.(env|key|pem)[^\n]*do[^\n]*(curl|wget|nc)/gi,
        risk: 'critical',
        title: 'Batch exfiltrate sensitive files',
        description: 'Loop reading and sending multiple sensitive files'
      },
      {
        pattern: /find\s+[^\n]*-exec[^\n]*(curl|wget|nc)[^\n]*\{\}/gi,
        risk: 'critical',
        title: 'Find + exfil combo',
        description: 'Searching files and executing exfiltration on each'
      },
      {
        pattern: /tar\s+[^\n]*\|\s*(curl|nc|base64)/gi,
        risk: 'critical',
        title: 'Archive and exfiltrate',
        description: 'Archiving multiple files and sending directly'
      },
      {
        pattern: /zip\s+[^\n]*&&[^\n]*(curl|wget|scp)/gi,
        risk: 'critical',
        title: 'Compress and upload',
        description: 'Compressing files then uploading externally'
      }
    ];

    // ===== Environment Variable Theft =====
    this.envTheftPatterns = [
      {
        pattern: /env\s*\|\s*(curl|wget|nc)/gi,
        risk: 'critical',
        title: 'Environment variable exfiltration',
        description: 'Sending all environment variables externally'
      },
      {
        pattern: /printenv\s*\|\s*(curl|wget|nc|base64)/gi,
        risk: 'critical',
        title: 'printenv exfiltration',
        description: 'Listing and sending all environment variables'
      },
      {
        pattern: /echo\s+\$[A-Z_]+(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[^\n]*(curl|wget)/gi,
        risk: 'critical',
        title: 'Sensitive env var exfiltration',
        description: 'Sending sensitive environment variables'
      },
      {
        pattern: /set\s*\|\s*(grep|curl|wget)/gi,
        risk: 'high',
        title: 'Shell variable exfiltration',
        description: 'Listing and possibly sending shell variables'
      }
    ];

    // ===== System Reconnaissance =====
    this.reconPatterns = [
      {
        pattern: /(whoami|id|hostname|uname\s+-a)[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'high',
        title: 'System info exfiltration',
        description: 'Collecting and sending system identification info'
      },
      {
        pattern: /ifconfig|ip\s+addr[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'high',
        title: 'Network config exfiltration',
        description: 'Sending network configuration info'
      },
      {
        pattern: /ps\s+(aux|ef)[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'medium',
        title: 'Process list exfiltration',
        description: 'Sending system process list'
      },
      {
        pattern: /netstat|ss\s+-[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'high',
        title: 'Network connection exfiltration',
        description: 'Sending system network connection info'
      },
      {
        pattern: /lsof[^\n]*\|\s*(curl|wget|nc)/gi,
        risk: 'medium',
        title: 'Open file list exfiltration',
        description: 'Sending list of open files'
      }
    ];

    // ===== Persistence Mechanisms =====
    this.persistencePatterns = [
      {
        pattern: /crontab\s+-[el]?[^\n]*curl|wget/gi,
        risk: 'critical',
        title: 'Cron scheduled exfiltration',
        description: 'Setting up scheduled task for persistent data exfiltration'
      },
      {
        pattern: /echo[^\n]*>>\s*~?\/?\.bashrc/gi,
        risk: 'high',
        title: 'Modifying .bashrc',
        description: 'Modifying shell startup file, may plant backdoor'
      },
      {
        pattern: /echo[^\n]*>>\s*~?\/?\.profile/gi,
        risk: 'high',
        title: 'Modifying .profile',
        description: 'Modifying user profile, may plant backdoor'
      },
      {
        pattern: /systemctl\s+(enable|start)[^\n]*/gi,
        risk: 'medium',
        title: 'Enabling system service',
        description: 'Enabling system service, may be used for persistence'
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

    // Scan all pattern categories
    const allPatternGroups = [
      { name: 'Data Collection', patterns: this.dataCollectionPatterns },
      { name: 'Data Exfiltration', patterns: this.exfiltrationPatterns },
      { name: 'Combined Attack', patterns: this.combinedPatterns },
      { name: 'Env Theft', patterns: this.envTheftPatterns },
      { name: 'System Recon', patterns: this.reconPatterns },
      { name: 'Persistence', patterns: this.persistencePatterns }
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

    // Check compound behaviors
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
    // Check if both read and send behaviors exist
    const hasRead = /cat\s+|head\s+|tail\s+|less\s+|more\s+|find\s+|grep\s+/gi.test(content);
    const hasSend = /curl\s+|wget\s+|nc\s+|scp\s+|ftp\s+|rsync\s+/gi.test(content);
    const hasEncode = /base64|gzip|tar\s+|zip\s+/gi.test(content);

    if (hasRead && hasSend) {
      findings.high.push({
        title: '[Behavior] Read + Send combination',
        description: 'Skill contains both file reading and network sending commands, may be used for data exfiltration',
        scanner: 'DataExfiltrationScanner'
      });
    }

    if (hasRead && hasSend && hasEncode) {
      findings.critical.push({
        title: '[Behavior] Full exfiltration toolchain',
        description: 'Skill contains read, encode, and send - a complete data exfiltration toolchain',
        scanner: 'DataExfiltrationScanner'
      });
    }

    // Check sensitive path access
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
        title: '[Behavior] Massive sensitive path access',
        description: `Detected access to ${sensitiveAccessCount} sensitive paths, highly suspicious`,
        scanner: 'DataExfiltrationScanner'
      });
    }

    // Check loop exfiltration pattern
    const hasLoop = /for\s+|while\s+|until\s+/gi.test(content);
    if (hasLoop && hasSend) {
      findings.high.push({
        title: '[Behavior] Loop network operation',
        description: 'Network sending in loop, may batch exfiltrate data',
        scanner: 'DataExfiltrationScanner'
      });
    }
  }
}
