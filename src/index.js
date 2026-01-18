#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { SkillDownloader } from './utils/downloader.js';
import { SecurityScanner } from './scanner/index.js';
import { SkillInstaller } from './utils/installer.js';

const program = new Command();

program
  .name('skill-install')
  .description('A secure Claude Skills installer with malicious operation detection')
  .version('1.0.0');

program
  .argument('<source>', 'Skill URL (SkillsMP link) or local path')
  .option('-o, --output <path>', 'Installation directory', './skills')
  .option('-f, --force', 'Skip security confirmation prompts', false)
  .option('-v, --verbose', 'Show detailed scan results', false)
  .option('--scan-only', 'Only scan without installing', false)
  .option('--allow-high-risk', 'Allow installation even with high-risk findings (not recommended)', false)
  .action(async (source, options) => {
    console.log(chalk.cyan.bold('\n🔧 Claude Skill Installer v1.0.0\n'));

    const spinner = ora();

    try {
      // Step 1: Download/Load the skill
      spinner.start('Fetching skill content...');
      const downloader = new SkillDownloader();
      const skillContent = await downloader.fetch(source);
      spinner.succeed(`Skill loaded: ${chalk.green(skillContent.name)}`);

      // Step 2: Security scan
      console.log(chalk.yellow('\n📋 Starting security scan...\n'));
      const scanner = new SecurityScanner(options.verbose);
      const scanResult = await scanner.scan(skillContent);

      // Step 3: Display scan results
      displayScanResults(scanResult, options.verbose);

      // Step 4: Decision based on scan
      if (options.scanOnly) {
        console.log(chalk.blue('\n✓ Scan complete (--scan-only mode)\n'));
        process.exit(0);
      }

      if (scanResult.riskLevel === 'CRITICAL' && !options.allowHighRisk) {
        console.log(chalk.red.bold('\n❌ Installation blocked due to CRITICAL security risks.'));
        console.log(chalk.yellow('Use --allow-high-risk to override (not recommended)\n'));
        process.exit(1);
      }

      // Step 5: User confirmation
      if (!options.force && scanResult.riskLevel !== 'SAFE') {
        const { proceed } = await inquirer.prompt([{
          type: 'confirm',
          name: 'proceed',
          message: `Skill has ${scanResult.riskLevel} risk level. Continue with installation?`,
          default: scanResult.riskLevel === 'LOW'
        }]);

        if (!proceed) {
          console.log(chalk.yellow('\n⚠ Installation cancelled by user.\n'));
          process.exit(0);
        }
      }

      // Step 6: Install
      spinner.start('Installing skill...');
      const installer = new SkillInstaller(options.output);
      const installPath = await installer.install(skillContent);
      spinner.succeed(`Skill installed to: ${chalk.green(installPath)}`);

      console.log(chalk.green.bold('\n✅ Installation complete!\n'));

    } catch (error) {
      spinner.fail(chalk.red('Error: ' + error.message));
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

function displayScanResults(result, verbose) {
  const riskColors = {
    'SAFE': chalk.green,
    'LOW': chalk.blue,
    'MEDIUM': chalk.yellow,
    'HIGH': chalk.hex('#FFA500'),
    'CRITICAL': chalk.red
  };

  const riskColor = riskColors[result.riskLevel] || chalk.white;

  console.log(chalk.bold('═══════════════════════════════════════════════════════'));
  console.log(chalk.bold('                    SECURITY SCAN REPORT                '));
  console.log(chalk.bold('═══════════════════════════════════════════════════════'));

  console.log(`\n${chalk.bold('Risk Level:')} ${riskColor.bold(result.riskLevel)}`);
  console.log(`${chalk.bold('Score:')} ${result.score}/100 ${getScoreBar(result.score)}`);

  // Summary stats
  console.log(`\n${chalk.bold('Findings Summary:')}`);
  console.log(`  ${chalk.red('Critical:')} ${result.findings.critical.length}`);
  console.log(`  ${chalk.hex('#FFA500')('High:')} ${result.findings.high.length}`);
  console.log(`  ${chalk.yellow('Medium:')} ${result.findings.medium.length}`);
  console.log(`  ${chalk.blue('Low:')} ${result.findings.low.length}`);
  console.log(`  ${chalk.green('Info:')} ${result.findings.info.length}`);

  // Detailed findings
  if (result.findings.critical.length > 0) {
    console.log(chalk.red.bold('\n🚨 CRITICAL ISSUES:'));
    result.findings.critical.forEach(f => {
      console.log(chalk.red(`  • ${f.title}`));
      console.log(chalk.gray(`    ${f.description}`));
      if (f.location) console.log(chalk.gray(`    Location: ${f.location}`));
    });
  }

  if (result.findings.high.length > 0) {
    console.log(chalk.hex('#FFA500').bold('\n⚠️  HIGH RISK ISSUES:'));
    result.findings.high.forEach(f => {
      console.log(chalk.hex('#FFA500')(`  • ${f.title}`));
      console.log(chalk.gray(`    ${f.description}`));
      if (f.location) console.log(chalk.gray(`    Location: ${f.location}`));
    });
  }

  if (verbose || result.riskLevel === 'SAFE') {
    if (result.findings.medium.length > 0) {
      console.log(chalk.yellow.bold('\n⚡ MEDIUM ISSUES:'));
      result.findings.medium.forEach(f => {
        console.log(chalk.yellow(`  • ${f.title}`));
        console.log(chalk.gray(`    ${f.description}`));
      });
    }

    if (result.findings.low.length > 0) {
      console.log(chalk.blue.bold('\nℹ️  LOW ISSUES:'));
      result.findings.low.forEach(f => {
        console.log(chalk.blue(`  • ${f.title}`));
      });
    }

    if (result.findings.info.length > 0) {
      console.log(chalk.green.bold('\n✓ INFO:'));
      result.findings.info.forEach(f => {
        console.log(chalk.green(`  • ${f.title}`));
      });
    }
  }

  console.log(chalk.bold('\n═══════════════════════════════════════════════════════\n'));
}

function getScoreBar(score) {
  const filled = Math.round(score / 10);
  const empty = 10 - filled;
  let color = chalk.green;
  if (score < 40) color = chalk.red;
  else if (score < 60) color = chalk.hex('#FFA500');
  else if (score < 80) color = chalk.yellow;

  return color('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
}

program.parse();
