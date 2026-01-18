/**
 * Internationalization (i18n) module for Claude Skill Antivirus
 * Supports English (en) and Traditional Chinese (zh-TW)
 */

import { en } from './en.js';
import { zhTW } from './zh-TW.js';

const languages = {
  en,
  'zh-TW': zhTW,
};

// Default language
let currentLang = 'en';

/**
 * Set the current language
 * @param {string} lang - Language code ('en' or 'zh-TW')
 */
export function setLanguage(lang) {
  if (languages[lang]) {
    currentLang = lang;
  } else {
    console.warn(`Language '${lang}' not supported, falling back to 'en'`);
    currentLang = 'en';
  }
}

/**
 * Get the current language
 * @returns {string} Current language code
 */
export function getLanguage() {
  return currentLang;
}

/**
 * Get available languages
 * @returns {string[]} Array of supported language codes
 */
export function getAvailableLanguages() {
  return Object.keys(languages);
}

/**
 * Get a translated message by path
 * @param {string} path - Dot-notation path to the message (e.g., 'cli.title')
 * @param {object} params - Optional parameters for interpolation
 * @returns {string} Translated message
 */
export function t(path, params = {}) {
  const keys = path.split('.');
  let value = languages[currentLang];

  for (const key of keys) {
    if (value && typeof value === 'object' && key in value) {
      value = value[key];
    } else {
      // Fallback to English if key not found
      value = languages.en;
      for (const k of keys) {
        if (value && typeof value === 'object' && k in value) {
          value = value[k];
        } else {
          return path; // Return path if not found in any language
        }
      }
      break;
    }
  }

  if (typeof value !== 'string') {
    return path;
  }

  // Simple interpolation
  return value.replace(/\{(\w+)\}/g, (match, key) => {
    return params[key] !== undefined ? params[key] : match;
  });
}

/**
 * Get a nested translation object
 * @param {string} path - Dot-notation path to the object
 * @returns {object} Translated object
 */
export function getMessages(path) {
  const keys = path.split('.');
  let value = languages[currentLang];

  for (const key of keys) {
    if (value && typeof value === 'object' && key in value) {
      value = value[key];
    } else {
      // Fallback to English
      value = languages.en;
      for (const k of keys) {
        if (value && typeof value === 'object' && k in value) {
          value = value[k];
        } else {
          return {};
        }
      }
      break;
    }
  }

  return value || {};
}

/**
 * Create a translator function for a specific namespace
 * @param {string} namespace - The namespace prefix
 * @returns {function} Translator function
 */
export function createTranslator(namespace) {
  return (key, params = {}) => t(`${namespace}.${key}`, params);
}

export default {
  setLanguage,
  getLanguage,
  getAvailableLanguages,
  t,
  getMessages,
  createTranslator,
};
