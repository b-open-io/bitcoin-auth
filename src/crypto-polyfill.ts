/**
 * Crypto polyfill for Node.js environments where globalThis.crypto is not available.
 * Call this before importing bitcoin-auth in Node.js test environments like Playwright, Jest, etc.
 */
export function setupCryptoPolyfill(): void {
  // First, handle the case where globalThis.crypto doesn't exist
  if (typeof globalThis !== 'undefined' && !globalThis.crypto && typeof require !== 'undefined') {
    try {
      const { webcrypto } = require('node:crypto');
      if (webcrypto) {
        globalThis.crypto = webcrypto;
      }
    } catch {
      // Ignore if crypto module not available
    }
  }

  // Always ensure self.crypto is set if globalThis.crypto exists (for @bsv/sdk compatibility)
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    if (typeof self === 'undefined') {
      // Create self object with crypto if it doesn't exist (Node.js environment)
      // biome-ignore lint/suspicious/noExplicitAny: ok
      (globalThis as any).self = { crypto: globalThis.crypto };
    } else if (!self.crypto) {
      // Set self.crypto if self exists but doesn't have crypto
      self.crypto = globalThis.crypto;
    }
  }
}

/**
 * Auto-setup crypto polyfill when this module is imported.
 * This is the simplest way for users to fix crypto issues.
 */
setupCryptoPolyfill(); 