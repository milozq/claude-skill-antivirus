/**
 * SSRFScanner - Detects Server-Side Request Forgery and cloud attack patterns
 * 偵測 SSRF 和雲端攻擊模式
 */
export class SSRFScanner {
  constructor() {
    // 雲端 Metadata Endpoint（最危險）
    this.cloudMetadataEndpoints = [
      {
        pattern: /169\.254\.169\.254/g,
        risk: 'critical',
        title: 'AWS/GCP Metadata Endpoint',
        description: '嘗試存取雲端 metadata endpoint，可竊取 IAM 憑證'
      },
      {
        pattern: /metadata\.google\.internal/gi,
        risk: 'critical',
        title: 'GCP Metadata Endpoint',
        description: '嘗試存取 Google Cloud metadata'
      },
      {
        pattern: /169\.254\.170\.2/g,
        risk: 'critical',
        title: 'AWS ECS Metadata',
        description: '嘗試存取 AWS ECS container metadata'
      },
      {
        pattern: /100\.100\.100\.200/g,
        risk: 'critical',
        title: 'Alibaba Cloud Metadata',
        description: '嘗試存取阿里雲 metadata endpoint'
      },
      {
        pattern: /metadata\.azure\.(com|net)/gi,
        risk: 'critical',
        title: 'Azure Metadata Endpoint',
        description: '嘗試存取 Azure Instance Metadata Service'
      },
      {
        pattern: /\/latest\/meta-data|\/latest\/user-data|\/latest\/dynamic/gi,
        risk: 'critical',
        title: 'Cloud Metadata Path',
        description: '偵測到雲端 metadata 路徑模式'
      },
      {
        pattern: /\/computeMetadata\/v1/gi,
        risk: 'critical',
        title: 'GCP Compute Metadata',
        description: '嘗試存取 GCP compute metadata'
      },
      {
        pattern: /Metadata-Flavor:\s*Google/gi,
        risk: 'critical',
        title: 'GCP Metadata Header',
        description: '使用 GCP metadata 請求標頭'
      }
    ];

    // 內部網路探測
    this.internalNetworkPatterns = [
      {
        pattern: /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: '內部網路存取 (10.x.x.x)',
        description: '嘗試存取 Class A 私有網路'
      },
      {
        pattern: /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: '內部網路存取 (172.16-31.x.x)',
        description: '嘗試存取 Class B 私有網路'
      },
      {
        pattern: /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: '內部網路存取 (192.168.x.x)',
        description: '嘗試存取 Class C 私有網路'
      },
      {
        pattern: /https?:\/\/127\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
        risk: 'high',
        title: 'Loopback 存取',
        description: '嘗試存取 loopback 網路'
      },
      {
        pattern: /https?:\/\/0\.0\.0\.0/gi,
        risk: 'high',
        title: '存取 0.0.0.0',
        description: '嘗試存取所有網路介面'
      },
      {
        pattern: /https?:\/\/\[::1?\]/gi,
        risk: 'high',
        title: 'IPv6 Loopback',
        description: '嘗試存取 IPv6 loopback'
      },
      {
        pattern: /https?:\/\/localhost/gi,
        risk: 'medium',
        title: 'Localhost 存取',
        description: '存取 localhost，可能是 SSRF'
      }
    ];

    // 常見內部服務端口
    this.internalServicePatterns = [
      {
        pattern: /:\s*(6379|27017|5432|3306|9200|9300|11211|5672|15672|8500|2379)/g,
        risk: 'high',
        title: '內部服務端口探測',
        description: '偵測到常見內部服務端口（Redis、MongoDB、PostgreSQL、MySQL、Elasticsearch、Consul 等）'
      },
      {
        pattern: /:\s*(22|23|3389|5900)/g,
        risk: 'medium',
        title: '遠端管理端口',
        description: '偵測到 SSH、Telnet、RDP、VNC 端口'
      },
      {
        pattern: /:8080|:8443|:9000|:9090|:3000|:4000|:5000|:8000/g,
        risk: 'low',
        title: '常見開發端口',
        description: '偵測到常見 Web 開發端口'
      }
    ];

    // SSRF Bypass 技術
    this.ssrfBypassPatterns = [
      {
        pattern: /0x[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+/gi,
        risk: 'critical',
        title: 'SSRF Bypass - Hex IP',
        description: '使用十六進位 IP 繞過過濾'
      },
      {
        pattern: /\d{8,10}/g,  // 十進位 IP (e.g., 2130706433 = 127.0.0.1)
        risk: 'medium',
        title: '可能的十進位 IP',
        description: '大數字可能是十進位 IP 編碼'
      },
      {
        pattern: /%2f%2f|%252f|%00/gi,
        risk: 'high',
        title: 'URL 編碼繞過',
        description: '使用 URL 編碼嘗試繞過過濾'
      },
      {
        pattern: /@|#.*@/g,
        risk: 'medium',
        title: 'URL Authority 混淆',
        description: '使用 @ 符號可能進行 URL 混淆攻擊'
      },
      {
        pattern: /\\\\[a-z0-9.-]+\\/gi,
        risk: 'high',
        title: 'UNC 路徑',
        description: '使用 UNC 路徑可能存取網路共享'
      },
      {
        pattern: /file:\/\//gi,
        risk: 'critical',
        title: 'File Protocol',
        description: '使用 file:// 協議讀取本地檔案'
      },
      {
        pattern: /gopher:\/\//gi,
        risk: 'critical',
        title: 'Gopher Protocol',
        description: 'Gopher 協議常用於 SSRF 攻擊'
      },
      {
        pattern: /dict:\/\//gi,
        risk: 'high',
        title: 'Dict Protocol',
        description: 'Dict 協議可用於探測服務'
      },
      {
        pattern: /ldap:\/\/|ldaps:\/\//gi,
        risk: 'high',
        title: 'LDAP Protocol',
        description: 'LDAP 協議可能導致資訊洩漏'
      }
    ];

    // Kubernetes 特定攻擊
    this.kubernetesPatterns = [
      {
        pattern: /kubernetes\.default|\.svc\.cluster\.local/gi,
        risk: 'critical',
        title: 'Kubernetes 內部服務',
        description: '嘗試存取 Kubernetes 內部服務'
      },
      {
        pattern: /\/api\/v1\/namespaces|\/apis\//gi,
        risk: 'critical',
        title: 'Kubernetes API 路徑',
        description: '嘗試存取 Kubernetes API'
      },
      {
        pattern: /kube-system|kube-public|default/gi,
        risk: 'medium',
        title: 'Kubernetes Namespace',
        description: '引用 Kubernetes 系統 namespace'
      },
      {
        pattern: /serviceaccount|\.kube\/config/gi,
        risk: 'high',
        title: 'Kubernetes 認證',
        description: '嘗試存取 Kubernetes 認證資訊'
      }
    ];

    // Docker 特定攻擊
    this.dockerPatterns = [
      {
        pattern: /\/var\/run\/docker\.sock/gi,
        risk: 'critical',
        title: 'Docker Socket 存取',
        description: '嘗試存取 Docker socket，可接管主機'
      },
      {
        pattern: /docker\s+(exec|run|cp)/gi,
        risk: 'high',
        title: 'Docker 命令執行',
        description: '執行 Docker 命令'
      },
      {
        pattern: /--privileged|--cap-add/gi,
        risk: 'critical',
        title: 'Docker 特權模式',
        description: '使用 Docker 特權模式或增加 capabilities'
      }
    ];

    // AWS 特定攻擊
    this.awsPatterns = [
      {
        pattern: /iam\/security-credentials/gi,
        risk: 'critical',
        title: 'AWS IAM 憑證存取',
        description: '嘗試從 metadata 取得 IAM 憑證'
      },
      {
        pattern: /identity-credentials\/ec2/gi,
        risk: 'critical',
        title: 'AWS EC2 Identity',
        description: '嘗試取得 EC2 身份憑證'
      },
      {
        pattern: /X-aws-ec2-metadata-token/gi,
        risk: 'high',
        title: 'AWS IMDSv2 Token',
        description: '偵測 AWS IMDSv2 token 請求'
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
      { name: '雲端 Metadata', patterns: this.cloudMetadataEndpoints },
      { name: '內部網路', patterns: this.internalNetworkPatterns },
      { name: '內部服務', patterns: this.internalServicePatterns },
      { name: 'SSRF 繞過', patterns: this.ssrfBypassPatterns },
      { name: 'Kubernetes', patterns: this.kubernetesPatterns },
      { name: 'Docker', patterns: this.dockerPatterns },
      { name: 'AWS', patterns: this.awsPatterns }
    ];

    for (const group of allPatternGroups) {
      for (const { pattern, risk, title, description } of group.patterns) {
        // Reset regex lastIndex
        pattern.lastIndex = 0;
        const matches = content.match(pattern);
        if (matches) {
          findings[risk].push({
            title: `[${group.name}] ${title}`,
            description,
            matches: [...new Set(matches)].slice(0, 3),
            category: group.name,
            scanner: 'SSRFScanner'
          });
        }
      }
    }

    // 複合行為分析
    this.analyzeCompoundBehaviors(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  analyzeCompoundBehaviors(content, findings) {
    // 檢查是否有網路請求工具 + 內部 IP
    const hasNetworkTools = /curl|wget|fetch|http\.get|requests\.|axios|WebFetch/gi.test(content);
    const hasInternalIP = /10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\./g.test(content);
    const hasMetadata = /169\.254\.169\.254|metadata/gi.test(content);

    if (hasNetworkTools && hasMetadata) {
      findings.critical.push({
        title: '[行為分析] 網路工具 + Metadata 存取',
        description: 'Skill 包含網路請求工具和雲端 metadata endpoint，高度可疑的 SSRF 攻擊',
        scanner: 'SSRFScanner'
      });
    }

    if (hasNetworkTools && hasInternalIP) {
      findings.high.push({
        title: '[行為分析] 網路工具 + 內部 IP',
        description: 'Skill 包含網路請求工具和內部 IP 位址，可能探測內部網路',
        scanner: 'SSRFScanner'
      });
    }

    // 檢查動態 URL 構造
    const hasDynamicUrl = /\$\{.*\}.*https?:|https?:.*\$\{|url\s*=.*\+|fetch\s*\([^)]*\+/gi.test(content);
    if (hasDynamicUrl) {
      findings.medium.push({
        title: '[行為分析] 動態 URL 構造',
        description: '偵測到動態構造 URL 的模式，可能允許 SSRF 注入',
        scanner: 'SSRFScanner'
      });
    }
  }
}
