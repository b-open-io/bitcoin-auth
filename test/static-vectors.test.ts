import { describe, it, expect } from "bun:test";
import { verifyAuthToken, getAuthToken, parseAuthToken } from "../src/auth";
import type { AuthPayload } from "../src/types";
import { PrivateKey } from "@bsv/sdk";

interface StaticTestVector {
  description: string;
  token: string;
  payloadToVerify: AuthPayload;
  expectedResult: boolean;
  timePad?: number;
  bodyEncoding?: 'utf8' | 'hex' | 'base64';
}

// --- Helper to generate tokens for our static vectors ---
// In a real scenario, these tokens would be pre-generated and stored.
// For this setup, we generate them once and use the output.

const fixedTimestamp1 = "2023-10-27T10:00:00.000Z";
const fixedTimestamp2 = "2023-10-27T11:00:00.000Z";

// Static keys (DO NOT USE IN PRODUCTION - FOR TESTING ONLY)
const staticPrivateKeyWifBrc77 = "L5JXt5QF39GECz23VqUMTs6gYx2s4R3rsjEz4bJ4wnJ6Su16VHur"; // Regenerated valid WIF
const staticPrivateKeyWifBsm = "KyAx8SM5W8AA7jHvcY9Lwq9WWYgt2mV2kN9xg6mUoTyRKdQiMXy8"; // Regenerated valid WIF

const staticTokenBrc77Body = getAuthToken({
  privateKeyWif: staticPrivateKeyWifBrc77,
  requestPath: "/api/static/brc77/body",
  body: JSON.stringify({ message: "static brc77 test" }),
  scheme: "brc77",
  timestamp: fixedTimestamp1 
});
const parsedBrc77Body = parseAuthToken(staticTokenBrc77Body);
if (!parsedBrc77Body) throw new Error("Failed to parse static BRC-77 token for tests");

const staticTokenBsmNoBody = getAuthToken({
  privateKeyWif: staticPrivateKeyWifBsm,
  requestPath: "/api/static/bsm/no-body?query=1",
  scheme: "bsm",
  timestamp: fixedTimestamp2 
});
const parsedBsmNoBody = parseAuthToken(staticTokenBsmNoBody);
if (!parsedBsmNoBody) throw new Error("Failed to parse static BSM token for tests");

// --- Static Test Vectors ---
const staticTestVectors: StaticTestVector[] = [
  {
    description: "BRC-77: Valid token with body",
    token: staticTokenBrc77Body,
    payloadToVerify: {
      requestPath: parsedBrc77Body.requestPath,
      timestamp: parsedBrc77Body.timestamp, // Use actual timestamp from generated token
      body: JSON.stringify({ message: "static brc77 test" }),
    },
    expectedResult: true,
    bodyEncoding: "utf8",
  },
  {
    description: "BRC-77: Tampered body",
    token: staticTokenBrc77Body,
    payloadToVerify: {
      requestPath: parsedBrc77Body.requestPath,
      timestamp: parsedBrc77Body.timestamp,
      body: JSON.stringify({ message: "TAMPERED static brc77 test" }),
    },
    expectedResult: false,
    bodyEncoding: "utf8",
  },
  {
    description: "BRC-77: Tampered requestPath",
    token: staticTokenBrc77Body,
    payloadToVerify: {
      requestPath: "/api/static/brc77/TAMPERED_PATH",
      timestamp: parsedBrc77Body.timestamp,
      body: JSON.stringify({ message: "static brc77 test" }),
    },
    expectedResult: false,
    bodyEncoding: "utf8",
  },
  {
    description: "BRC-77: Timestamp too old (outside default 5 min window)",
    token: staticTokenBrc77Body, // Assumes token was generated at fixedTimestamp1
    payloadToVerify: {
      requestPath: parsedBrc77Body.requestPath,
      // Current time will be much later than fixedTimestamp1, making the token appear too old
      // To make this test reliable, we'd ideally mock Date.now() or pass a target timestamp to verifyAuthToken
      // For now, we set the target timestamp to be far in the past of token's timestamp.
      timestamp: new Date(new Date(parsedBrc77Body.timestamp).getTime() - 10 * 60 * 1000).toISOString(), // 10 mins before token's timestamp
      body: JSON.stringify({ message: "static brc77 test" }),
    },
    expectedResult: false, // This relies on the timePad logic in verifyPreRequisites
    bodyEncoding: "utf8",
  },
  {
    description: "BRC-77: Timestamp too far in future (outside default 5 min window)",
    // For this specific test, generate a token with a future timestamp
    token: getAuthToken({
      privateKeyWif: staticPrivateKeyWifBrc77,
      requestPath: parsedBrc77Body.requestPath, // Use same path as other BRC77 tests for consistency
      body: JSON.stringify({ message: "static brc77 test" }),
      scheme: "brc77",
      timestamp: new Date(new Date(fixedTimestamp1).getTime() + 15 * 60 * 1000).toISOString(), // Token is 15 mins in future relative to fixedTimestamp1
    }),
    payloadToVerify: {
      requestPath: parsedBrc77Body.requestPath,
      timestamp: fixedTimestamp1, // Verification happens "now" (fixedTimestamp1)
      body: JSON.stringify({ message: "static brc77 test" }),
    },
    expectedResult: false, 
    bodyEncoding: "utf8",
  },
  {
    description: "BSM: Valid token without body",
    token: staticTokenBsmNoBody,
    payloadToVerify: {
      requestPath: parsedBsmNoBody.requestPath,
      timestamp: parsedBsmNoBody.timestamp, // Use actual timestamp from generated token
      // No body
    },
    expectedResult: true,
  },
  {
    description: "BSM: Tampered requestPath",
    token: staticTokenBsmNoBody,
    payloadToVerify: {
      requestPath: "/api/static/bsm/TAMPERED_PATH?query=1",
      timestamp: parsedBsmNoBody.timestamp,
    },
    expectedResult: false,
  },
];

describe("Static Test Vector Verification", () => {
  for (const vector of staticTestVectors) {
    it(vector.description, () => {
      const isValid = verifyAuthToken(
        vector.token,
        vector.payloadToVerify,
        vector.timePad,      // Will be undefined if not set, using default
        vector.bodyEncoding  // Will be undefined if not set, using default
      );
      expect(isValid).toBe(vector.expectedResult);
    });
  }

  // Test to ensure our token generation for tests is somewhat stable for key parts
  it("should ensure static BRC-77 token structure is as expected for tests", () => {
    const parsed = parseAuthToken(staticTokenBrc77Body);
    expect(parsed).not.toBeNull();
    expect(parsed?.scheme).toBe("brc77");
    expect(parsed?.requestPath).toBe("/api/static/brc77/body");
    // Signature and pubkey will vary with private key, but timestamp is fixed for generation.
    expect(parsed?.timestamp).toBe(fixedTimestamp1);
  });

  it("should ensure static BSM token structure is as expected for tests", () => {
    const parsed = parseAuthToken(staticTokenBsmNoBody);
    expect(parsed).not.toBeNull();
    expect(parsed?.scheme).toBe("bsm");
    expect(parsed?.requestPath).toBe("/api/static/bsm/no-body?query=1");
    expect(parsed?.timestamp).toBe(fixedTimestamp2);
  });
}); 