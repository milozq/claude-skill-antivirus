import { mkdir, writeFile } from 'fs/promises';
import path from 'path';
import os from 'os';

/**
 * SkillInstaller - Handles the actual installation of skills
 *
 * Installation paths:
 * - User level (--global): ~/.claude/skills/
 * - Project level (default): ./.claude/skills/
 */
export class SkillInstaller {
  constructor(options = {}) {
    this.global = options.global || false;
    this.outputDir = this.getOutputDir();
  }

  getOutputDir() {
    if (this.global) {
      // User level: ~/.claude/skills/
      return path.join(os.homedir(), '.claude', 'skills');
    } else {
      // Project level: ./.claude/skills/
      return path.join(process.cwd(), '.claude', 'skills');
    }
  }

  /**
   * Install a skill to the output directory
   * @param {SkillContent} skillContent - Parsed skill content
   * @returns {Promise<string>} - Installation path
   */
  async install(skillContent) {
    const skillDir = path.join(this.outputDir, this.sanitizeName(skillContent.name));

    // Create directory
    await mkdir(skillDir, { recursive: true });

    // Write all files
    for (const file of skillContent.files) {
      const filePath = path.join(skillDir, file.path);
      const fileDir = path.dirname(filePath);

      await mkdir(fileDir, { recursive: true });
      await writeFile(filePath, file.content, 'utf-8');
    }

    // Write metadata file
    const metadataPath = path.join(skillDir, '.skill-meta.json');
    await writeFile(metadataPath, JSON.stringify({
      name: skillContent.name,
      source: skillContent.source,
      installedAt: new Date().toISOString(),
      metadata: skillContent.metadata
    }, null, 2), 'utf-8');

    return skillDir;
  }

  sanitizeName(name) {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9-_]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }
}
