import { beforeEach, describe, expect, it, jest } from 'bun:test';
import {
  BSM,
  Hash,
  PrivateKey,
  SignedMessage as SDKSignedMessage,
  Utils,
} from '@bsv/sdk';
import { getAuthToken, parseAuthToken, verifyAuthToken } from '../src/auth';
import type { AuthPayload } from '../src/types';

const { toArray, toBase64, toHex } = Utils;

describe('Auth Token Utilities', () => {
  let privateKey: PrivateKey;
  let publicKeyHex: string;
  const requestPathWithoutQuery = '/test/auth_path';
  const requestPathWithQuery =
    '/test/auth_path?param1=value1&another=val2&third=true';
  const requestBody = JSON.stringify({ data: 'testPayload', value: 123 }); // Sample request body
  const requestBodyHex = toHex(toArray(requestBody, 'utf8'));
  const requestBodyBase64 = toBase64(toArray(requestBody, 'utf8'));

  beforeEach(() => {
    privateKey = PrivateKey.fromRandom();
    publicKeyHex = privateKey.toPublicKey().toString();
  });

  // Test suite for 'brc77' (BRC-77) scheme
  describe("BRC-77 ('brc77' scheme)", () => {
    const scheme = 'brc77';
    it(`[${scheme} scheme] should generate a valid token with body (no query params)`, async () => {
      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        body: requestBody,
        scheme,
      });
      expect(typeof token).toBe('string');
      const parsed = parseAuthToken(token);
      expect(parsed?.pubkey).toBe(publicKeyHex);
      expect(parsed?.requestPath).toBe(requestPathWithoutQuery);
      expect(parsed?.timestamp).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
      expect(typeof parsed?.signature).toBe('string');
      expect(parsed?.signature.length).toBeGreaterThan(0);
    });

    it(`[${scheme} scheme] should generate a valid token with body (with query params)`, async () => {
      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithQuery,
        body: requestBody,
        bodyEncoding: 'utf8',
        scheme,
      });
      expect(typeof token).toBe('string');
      const parsed = parseAuthToken(token);
      expect(parsed?.pubkey).toBe(publicKeyHex);
      expect(parsed?.requestPath).toBe(requestPathWithQuery);
      expect(parsed?.timestamp).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
      expect(typeof parsed?.signature).toBe('string');
      expect(parsed?.signature.length).toBeGreaterThan(0);
    });

    it(`[${scheme} scheme] should generate a valid token without body`, async () => {
      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        scheme,
      }); // body is undefined
      expect(typeof token).toBe('string');
      const parsed = parseAuthToken(token);
      expect(parsed?.pubkey).toBe(publicKeyHex);
    });

    it(`[${scheme} scheme] verifyAuthToken should return true for a valid token with body`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        body: requestBody,
        scheme,
      });
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: tokenTimestampStr,
        body: requestBody,
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(true);
    });

    it(`[${scheme} scheme] verifyAuthToken should return true for a valid token with body (with query params)`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithQuery,
        body: requestBody,
        scheme,
        bodyEncoding: 'utf8',
      });
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithQuery,
        timestamp: tokenTimestampStr,
        body: requestBody,
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(true);
    });

    it(`[${scheme} scheme] verifyAuthToken should return true for a valid token (explicitly no body)`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithQuery,
        scheme,
      }); // body is undefined
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithQuery,
        timestamp: tokenTimestampStr,
        // no body in target
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(true);
    });

    it(`[${scheme} scheme] verifyAuthToken should return false for a valid token with body mismatch`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        body: requestBody,
        scheme,
      });
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: tokenTimestampStr,
        body: 'different body',
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(false);
    });

    // it(`[${scheme} scheme] verifyAuthToken should correctly use SignedMessage.verify`, async () => {
    //   ...
    // });
  });

  // Test suite for legacy 'bsm' scheme
  describe("Legacy BSM ('bsm' scheme)", () => {
    const scheme = 'bsm';
    it(`[${scheme} scheme] should generate a valid token with body (with query params)`, async () => {
      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithQuery,
        body: requestBody,
        scheme,
      });
      expect(typeof token).toBe('string');
      const parsed = parseAuthToken(token);
      expect(parsed?.pubkey).toBe(publicKeyHex);
      expect(parsed?.requestPath).toBe(requestPathWithQuery);
      // ... other assertions similar to 'brc77' scheme generation ...
    });

    it(`[${scheme} scheme] should generate a valid token without body`, async () => {
      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        scheme,
      }); // body is undefined
      expect(typeof token).toBe('string');
      const parsed = parseAuthToken(token);
      expect(parsed?.pubkey).toBe(publicKeyHex);
      // ... other assertions
    });

    it(`[${scheme} scheme] verifyAuthToken should return true for a valid token with body`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        body: requestBody,
        scheme,
      });
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: tokenTimestampStr,
        body: requestBody,
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(true);
    });

    it(`[${scheme} scheme] verifyAuthToken should return true for a valid token with body (with query params)`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithQuery,
        body: requestBody,
        scheme,
        bodyEncoding: 'utf8',
      });
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithQuery,
        timestamp: tokenTimestampStr,
        body: requestBody,
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(true);
    });

    it(`[${scheme} scheme] verifyAuthToken should return true for a valid token (explicitly no body)`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithQuery,
        scheme,
      }); // body is undefined
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithQuery,
        timestamp: tokenTimestampStr,
        // no body in target
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(true);
    });

    it(`[${scheme} scheme] verifyAuthToken should return false for a valid token with body mismatch`, async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(() => tokenTimestampStr) as jest.Mock<
        () => string
      >;

      const token = getAuthToken({
        privateKeyWif: privateKey.toWif(),
        requestPath: requestPathWithoutQuery,
        body: requestBody,
        scheme,
      });
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: tokenTimestampStr,
        body: 'different body',
      };
      expect(verifyAuthToken(token, targetPayload, 5, 'utf8')).toBe(false);
    });

    it(`[${scheme} scheme] verifyAuthToken should correctly use BSM.verify with body (with query params)`, async () => {
      const tokenTimestamp = new Date().toISOString();
      const bodyHashFromTest = toHex(Hash.sha256(toArray(requestBody)));
      const messageToSign = `${requestPathWithQuery}|${tokenTimestamp}|${bodyHashFromTest}`;
      const signatureBase64 = BSM.sign(
        toArray(messageToSign),
        privateKey,
      ) as string;
      const token = `${publicKeyHex}|${scheme}|${tokenTimestamp}|${requestPathWithQuery}|${signatureBase64}`;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithQuery,
        timestamp: tokenTimestamp,
        body: requestBody,
      };
      const isValid = verifyAuthToken(token, targetPayload);
      expect(isValid).toBe(true);

      // Test against a BRC-77/BSV SDK SignedMessage (should fail BSM verification)
      const bsvSignatureBytes = SDKSignedMessage.sign(
        toArray(messageToSign),
        privateKey,
      );
      const bsvSignatureBase64 = toBase64(bsvSignatureBytes);
      const bsvToken = `${publicKeyHex}|${scheme}|${tokenTimestamp}|${requestPathWithQuery}|${bsvSignatureBase64}`;
      expect(() => verifyAuthToken(bsvToken, targetPayload)).toThrowError(); // Expecting an error due to signature format mismatch
    });

    it(`[${scheme} scheme] verifyAuthToken should correctly use BSM.verify without body (with query params)`, async () => {
      const tokenTimestamp = new Date().toISOString();
      const bodyHash = ''; // Empty body hash
      const messageToSign = `${requestPathWithQuery}|${tokenTimestamp}|${bodyHash}`;
      const signatureBase64 = BSM.sign(
        toArray(messageToSign),
        privateKey,
      ) as string;
      const token = `${publicKeyHex}|${scheme}|${tokenTimestamp}|${requestPathWithQuery}|${signatureBase64}`;

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithQuery,
        timestamp: tokenTimestamp,
      }; // No body in target
      const isValid = verifyAuthToken(token, targetPayload);
      expect(isValid).toBe(true);
    });
  });

  // Common verification logic tests (using verifyPreRequisites indirectly via verifyAuthToken default 'brc77' scheme)
  describe("Common Verification Logic (via verifyAuthToken default 'brc77' scheme)", () => {
    const scheme = 'brc77';
    it('should return false if token timestamp is too far in the future', async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(
        () => tokenTimestampStr,
      ) as jest.Mock<() => string>;
      const token = getAuthToken(
        {
          privateKeyWif: privateKey.toWif(),
          requestPath: requestPathWithQuery,
          scheme,
        },
      );
      Date.prototype.toISOString = originalDateToISOString;

      const targetTimestamp = new Date(tokenTimestamp);
      targetTimestamp.setMinutes(tokenTimestamp.getMinutes() - 10);

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: targetTimestamp.toISOString(),
      };
      expect(verifyAuthToken(token, targetPayload)).toBe(false);
    });

    it('should return true if token timestamp is just within future padding', async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(
        () => tokenTimestampStr,
      ) as jest.Mock<() => string>;
      const token = getAuthToken(
        {
          privateKeyWif: privateKey.toWif(),
          requestPath: requestPathWithoutQuery,
          scheme,
        },
      );
      Date.prototype.toISOString = originalDateToISOString;

      const targetTimestamp = new Date(tokenTimestamp);
      targetTimestamp.setMinutes(tokenTimestamp.getMinutes() - 4);

      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: targetTimestamp.toISOString(),
      };
      expect(verifyAuthToken(token, targetPayload)).toBe(true);
    });

    it('should return false for mismatched requestPath', async () => {
      const tokenTimestamp = new Date();
      const tokenTimestampStr = tokenTimestamp.toISOString();
      const originalDateToISOString = Date.prototype.toISOString;
      Date.prototype.toISOString = jest.fn(
        () => tokenTimestampStr,
      ) as jest.Mock<() => string>;
      const token = getAuthToken(
        {
          privateKeyWif: privateKey.toWif(),
          requestPath: requestPathWithoutQuery,
          scheme,
        },
      );
      Date.prototype.toISOString = originalDateToISOString;

      const targetPayload: AuthPayload = {
        requestPath: '/different/path',
        timestamp: tokenTimestampStr,
      };
      expect(verifyAuthToken(token, targetPayload)).toBe(false);
    });

    it('should return false for a malformed token (not enough parts)', async () => {
      const malformedToken = 'pubkey|timestamp|path'; // Directly use the malformed string
      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: new Date().toISOString(),
      };
      expect(verifyAuthToken(malformedToken, targetPayload)).toBe(false);
    });

    it('should return false if PublicKey.fromString fails (e.g. invalid pubkey string)', () => {
      const invalidPubKeyToken = `invalid-pubkey-string|${new Date().toISOString()}|${requestPathWithoutQuery}|somesignature`; // Direct string
      const target: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: new Date().toISOString(),
      };
      expect(verifyAuthToken(invalidPubKeyToken, target)).toBe(false);
    });
  });

  describe('parseAuthToken', () => {
    it('should correctly parse a valid token string', () => {
      const now = new Date().toISOString();
      const sig = 'testSignatureBase64';
      const scheme = 'brc77';
      const token = `${publicKeyHex}|${scheme}|${now}|${requestPathWithoutQuery}|${sig}`; // Direct string
      const parsed = parseAuthToken(token);
      expect(parsed?.pubkey).toBe(publicKeyHex);
      expect(parsed?.scheme).toBe(scheme);
      expect(parsed?.timestamp).toBe(now);
      expect(parsed?.requestPath).toBe(requestPathWithoutQuery);
      expect(parsed?.signature).toBe(sig);
    });
  });

  describe('Common Verification Logic', () => {
    it('parseAuthToken should return null for malformed token string', () => {
      const malformedToken = 'pubkey|timestamp|path'; // Directly use the malformed string
      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: new Date().toISOString(),
      };
      expect(parseAuthToken(malformedToken)).toBeNull();
    });

    it('verifyAuthToken should return false for token with invalid scheme', () => {
      const tokenTimestamp = new Date().toISOString();
      const targetPayload: AuthPayload = {
        requestPath: requestPathWithoutQuery,
        timestamp: tokenTimestamp,
      };
      // Manually construct a token with an invalid scheme
      const bodyHash = ''; // Assuming no body for simplicity in this specific test
      const message = `${requestPathWithoutQuery}|${tokenTimestamp}|${bodyHash}`;
      const signature = toBase64(SDKSignedMessage.sign(toArray(message), privateKey));
      const malformedToken = `${publicKeyHex}|invalidScheme|${tokenTimestamp}|${requestPathWithoutQuery}|${signature}`;
      expect(verifyAuthToken(malformedToken, targetPayload, 5, 'utf8')).toBe(false);
    });

    // Test cases for different body encodings
    const encodings: Array<'utf8' | 'hex' | 'base64'> = [
      'utf8',
      'hex',
      'base64',
    ];
    const schemesToTest: Array<'brc77' | 'bsm'> = ['brc77', 'bsm'];

    for (const scheme of schemesToTest) {
      for (const encoding of encodings) {
        it(`[${scheme} scheme] should generate and verify token with bodyEncoding: ${encoding}`, async () => {
          const tokenTimestamp = new Date();
          const tokenTimestampStr = tokenTimestamp.toISOString();
          const originalDateToISOString = Date.prototype.toISOString;
          Date.prototype.toISOString = jest.fn(
            () => tokenTimestampStr,
          ) as jest.Mock<() => string>;

          let bodyToSend = requestBody;
          if (encoding === 'hex') {
            bodyToSend = requestBodyHex;
          } else if (encoding === 'base64') {
            bodyToSend = requestBodyBase64;
          }

          const token = getAuthToken({
            privateKeyWif: privateKey.toWif(),
            requestPath: requestPathWithoutQuery,
            body: bodyToSend,
            bodyEncoding: encoding,
            scheme,
          });
          Date.prototype.toISOString = originalDateToISOString;

          // When verifying, the target.body should be the original (utf8) string,
          // and verifyAuthToken will handle encoding it appropriately based on the bodyEncoding param.
          const targetPayload: AuthPayload = {
            requestPath: requestPathWithoutQuery,
            timestamp: tokenTimestampStr,
            body: bodyToSend,
          };

          // The bodyEncoding used for verification must match the one used for token generation
          expect(verifyAuthToken(token, targetPayload, 5, encoding)).toBe(true);

          // Test that verification fails if the wrong bodyEncoding is used for verification
          const wrongEncoding = encodings.find((enc) => enc !== encoding);
          if (wrongEncoding) {
            expect(
              verifyAuthToken(token, targetPayload, 5, wrongEncoding),
            ).toBe(false);
          }
        });

        it(`[${scheme} scheme] verifyAuthToken should return false for token with correct ${encoding} bodyEncoding but mismatched body content`, async () => {
          const tokenTimestamp = new Date();
          const tokenTimestampStr = tokenTimestamp.toISOString();
          const originalDateToISOString = Date.prototype.toISOString;
          Date.prototype.toISOString = jest.fn(
            () => tokenTimestampStr,
          ) as jest.Mock<() => string>;

          let bodyToSend = requestBody;
          if (encoding === 'hex') {
            bodyToSend = requestBodyHex;
          } else if (encoding === 'base64') {
            bodyToSend = requestBodyBase64;
          }
          
          const token = getAuthToken({
            privateKeyWif: privateKey.toWif(),
            requestPath: requestPathWithoutQuery,
            body: bodyToSend,
            bodyEncoding: encoding,
            scheme
          });
          Date.prototype.toISOString = originalDateToISOString;

          const targetPayload: AuthPayload = {
            requestPath: requestPathWithoutQuery,
            timestamp: tokenTimestampStr,
            body: "a different body content", // Mismatched body
          };
          expect(verifyAuthToken(token, targetPayload, 5, encoding)).toBe(false);
        });
      }
    }
  });
});
