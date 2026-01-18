import { DangerousCommandScanner } from './dangerous-commands.js';
import { PermissionScanner } from './permissions.js';
import { ExternalConnectionScanner } from './external-connections.js';
import { PatternScanner } from './patterns.js';
import { DataExfiltrationScanner } from './data-exfiltration.js';
import { MCPSecurityScanner } from './mcp-security.js';
import { SSRFScanner } from './ssrf-scanner.js';
import { DependencyScanner } from './dependency-scanner.js';
import { SubAgentScanner } from './subagent-scanner.js';

/**
 * SecurityScanner - Main scanner that orchestrates all security checks
 * 整合型防毒掃描引擎，偵測 Skills 中的惡意行為
 *
 * 9 大掃描引擎：
 * 1. DangerousCommandScanner - 危險指令偵測
 * 2. PermissionScanner - 權限範圍檢查
 * 3. ExternalConnectionScanner - 外部連線分析
 * 4. PatternScanner - 惡意模式匹配
 * 5. DataExfiltrationScanner - 資料外洩偵測
 * 6. MCPSecurityScanner - MCP Server 安全檢查
 * 7. SSRFScanner - SSRF/雲端攻擊偵測
 * 8. DependencyScanner - 依賴安全檢查
 * 9. SubAgentScanner - Sub-agent 攻擊偵測
 */
export class SecurityScanner {
  constructor(verbose = false) {
    this.verbose = verbose;
    this.scanners = [
      new DangerousCommandScanner(),      // 危險指令偵測
      new PermissionScanner(),             // 權限範圍檢查
      new ExternalConnectionScanner(),     // 外部連線分析
      new PatternScanner(),                // 惡意模式匹配
      new DataExfiltrationScanner(),       // 資料外洩偵測
      new MCPSecurityScanner(),            // MCP Server 安全檢查
      new SSRFScanner(),                   // SSRF/雲端攻擊偵測
      new DependencyScanner(),             // 依賴安全檢查
      new SubAgentScanner()                // Sub-agent 攻擊偵測
    ];
  }

  /**
   * Run all security scans on the skill content
   * @param {SkillContent} skillContent
   * @returns {Promise<ScanResult>}
   */
  async scan(skillContent) {
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    // Run all scanners
    for (const scanner of this.scanners) {
      const scannerFindings = await scanner.scan(skillContent);
      this.mergeFindings(findings, scannerFindings);
    }

    // Calculate risk level and score
    const riskLevel = this.calculateRiskLevel(findings);
    const score = this.calculateScore(findings);

    return {
      skillName: skillContent.name,
      source: skillContent.source,
      scannedAt: new Date().toISOString(),
      riskLevel,
      score,
      findings,
      summary: this.generateSummary(findings, riskLevel)
    };
  }

  mergeFindings(target, source) {
    for (const level of Object.keys(target)) {
      if (source[level]) {
        target[level].push(...source[level]);
      }
    }
  }

  calculateRiskLevel(findings) {
    if (findings.critical.length > 0) return 'CRITICAL';
    if (findings.high.length > 0) return 'HIGH';
    if (findings.medium.length > 0) return 'MEDIUM';
    if (findings.low.length > 0) return 'LOW';
    return 'SAFE';
  }

  calculateScore(findings) {
    // Start with 100, deduct based on findings
    let score = 100;

    score -= findings.critical.length * 30;
    score -= findings.high.length * 20;
    score -= findings.medium.length * 10;
    score -= findings.low.length * 5;
    // Info doesn't affect score

    return Math.max(0, Math.min(100, score));
  }

  generateSummary(findings, riskLevel) {
    const total = Object.values(findings).reduce((sum, arr) => sum + arr.length, 0);

    return {
      totalFindings: total,
      riskLevel,
      recommendation: this.getRecommendation(riskLevel)
    };
  }

  getRecommendation(riskLevel) {
    const recommendations = {
      'CRITICAL': 'DO NOT INSTALL - This skill contains critical security risks that could harm your system.',
      'HIGH': 'Installation not recommended - Review all high-risk findings carefully before proceeding.',
      'MEDIUM': 'Proceed with caution - Some potentially risky patterns detected.',
      'LOW': 'Generally safe - Minor concerns detected, review before use.',
      'SAFE': 'Safe to install - No significant security concerns detected.'
    };
    return recommendations[riskLevel];
  }
}
