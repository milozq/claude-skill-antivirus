#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { SkillDownloader } from './utils/downloader.js';
import { SecurityScanner } from './scanner/index.js';
import { SkillInstaller } from './utils/installer.js';
import { setLanguage, t, getAvailableLanguages } from './i18n/index.js';

const program = new Command();

program
  .name('skill-install')
  .description('A secure Claude Skills installer with malicious operation detection')
  .version('2.0.1');

program
  .argument('<source>', 'Skill URL (SkillsMP link) or local path')
  .option('-g, --global', 'Install to user level (~/.claude/skills/)', false)
  .option('-f, --force', 'Skip security confirmation prompts', false)
  .option('-v, --verbose', 'Show detailed scan results', false)
  .option('-l, --lang <code>', 'Language (en, zh-TW)', 'en')
  .option('--scan-only', 'Only scan without installing', false)
  .option('--allow-high-risk', 'Allow installation even with high-risk findings (not recommended)', false)
  .action(async (source, options) => {
    // Set language first
    setLanguage(options.lang);

    console.log(chalk.cyan.bold(`\n🔧 ${t('cli.title')}\n`));

    const spinner = ora();

    try {
      // Step 1: Download/Load the skill
      spinner.start(t('cli.fetching'));
      const downloader = new SkillDownloader();
      const skillContent = await downloader.fetch(source);
      spinner.succeed(t('cli.skillLoaded', { name: chalk.green(skillContent.name) }));

      // Step 2: Security scan
      console.log(chalk.yellow(`\n📋 ${t('cli.startingScan')}\n`));
      const scanner = new SecurityScanner(options.verbose);
      const scanResult = await scanner.scan(skillContent);

      // Step 3: Display scan results
      displayScanResults(scanResult, options.verbose);

      // Step 4: Decision based on scan
      if (options.scanOnly) {
        console.log(chalk.blue(`\n✓ ${t('cli.scanComplete')}\n`));
        process.exit(0);
      }

      if (scanResult.riskLevel === 'CRITICAL' && !options.allowHighRisk) {
        console.log(chalk.red.bold(`\n❌ ${t('cli.installBlocked')}`));
        console.log(chalk.yellow(`${t('cli.useAllowHighRisk')}\n`));
        process.exit(1);
      }

      // Step 5: User confirmation
      if (!options.force && scanResult.riskLevel !== 'SAFE') {
        const { proceed } = await inquirer.prompt([{
          type: 'confirm',
          name: 'proceed',
          message: t('cli.confirmInstall', { riskLevel: scanResult.riskLevel }),
          default: scanResult.riskLevel === 'LOW'
        }]);

        if (!proceed) {
          console.log(chalk.yellow(`\n⚠ ${t('cli.installCancelled')}\n`));
          process.exit(0);
        }
      }

      // Step 6: Install
      spinner.start(t('cli.installing'));
      const installer = new SkillInstaller({ global: options.global });
      const installPath = await installer.install(skillContent);
      const levelText = options.global ? '(user level)' : '(project level)';
      spinner.succeed(t('cli.installedTo', { path: chalk.green(installPath) }) + ` ${chalk.gray(levelText)}`);

      console.log(chalk.green.bold(`\n✅ ${t('cli.installComplete')}\n`));

    } catch (error) {
      spinner.fail(chalk.red(`${t('cli.error')}: ${error.message}`));
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
  console.log(chalk.bold(`                    ${t('report.title')}                `));
  console.log(chalk.bold('═══════════════════════════════════════════════════════'));

  console.log(`\n${chalk.bold(t('report.riskLevel'))} ${riskColor.bold(result.riskLevel)}`);
  console.log(`${chalk.bold(t('report.score'))} ${result.score}/100 ${getScoreBar(result.score)}`);

  // Summary stats
  console.log(`\n${chalk.bold(t('report.findingsSummary'))}`);
  console.log(`  ${chalk.red(t('report.critical'))} ${result.findings.critical.length}`);
  console.log(`  ${chalk.hex('#FFA500')(t('report.high'))} ${result.findings.high.length}`);
  console.log(`  ${chalk.yellow(t('report.medium'))} ${result.findings.medium.length}`);
  console.log(`  ${chalk.blue(t('report.low'))} ${result.findings.low.length}`);
  console.log(`  ${chalk.green(t('report.info'))} ${result.findings.info.length}`);

  // Detailed findings
  if (result.findings.critical.length > 0) {
    console.log(chalk.red.bold(`\n🚨 ${t('report.criticalIssues')}`));
    result.findings.critical.forEach(f => {
      console.log(chalk.red(`  • ${f.title}`));
      console.log(chalk.gray(`    ${f.description}`));
      if (f.location) console.log(chalk.gray(`    ${t('report.location')}: ${f.location}`));
    });
  }

  if (result.findings.high.length > 0) {
    console.log(chalk.hex('#FFA500').bold(`\n⚠️  ${t('report.highIssues')}`));
    result.findings.high.forEach(f => {
      console.log(chalk.hex('#FFA500')(`  • ${f.title}`));
      console.log(chalk.gray(`    ${f.description}`));
      if (f.location) console.log(chalk.gray(`    ${t('report.location')}: ${f.location}`));
    });
  }

  if (verbose || result.riskLevel === 'SAFE') {
    if (result.findings.medium.length > 0) {
      console.log(chalk.yellow.bold(`\n⚡ ${t('report.mediumIssues')}`));
      result.findings.medium.forEach(f => {
        console.log(chalk.yellow(`  • ${f.title}`));
        console.log(chalk.gray(`    ${f.description}`));
      });
    }

    if (result.findings.low.length > 0) {
      console.log(chalk.blue.bold(`\nℹ️  ${t('report.lowIssues')}`));
      result.findings.low.forEach(f => {
        console.log(chalk.blue(`  • ${f.title}`));
      });
    }

    if (result.findings.info.length > 0) {
      console.log(chalk.green.bold(`\n✓ ${t('report.infoItems')}`));
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
