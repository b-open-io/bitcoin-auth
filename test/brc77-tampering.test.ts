import { describe, it, expect } from "bun:test";
import { getAuthToken, verifyAuthToken, parseAuthToken, type AuthPayload } from "../src/index";
import { PrivateKey } from "@bsv/sdk";

describe("BRC-77 Payload Tampering", () => {
  it("should fail verification if the body is tampered with", () => {
    const privateKeyWif = PrivateKey.fromRandom().toWif();
    const requestPath = "/api/data";
    const originalBody = JSON.stringify({ message: "original content" });
    const tamperedBody = JSON.stringify({ message: "tampered content" });

    // 1. Generate token with original body
    const tokenWithOriginalBody = getAuthToken({
      privateKeyWif,
      requestPath,
      body: originalBody,
      scheme: "brc77", // Explicitly BRC-77, though it's default
    });

    expect(tokenWithOriginalBody).toBeString();

    // 2. Parse the token to get the original timestamp (and other parts if needed)
    const parsedToken = parseAuthToken(tokenWithOriginalBody);
    expect(parsedToken).not.toBeNull();
    if (!parsedToken) return; // Type guard

    // 3. Construct payload for verification with TAMPERED body but ORIGINAL timestamp
    const payloadWithTamperedBody: AuthPayload = {
      requestPath: parsedToken.requestPath, // Use requestPath from token
      timestamp: parsedToken.timestamp,   // CRITICAL: Use timestamp from token
      body: tamperedBody,
    };

    // 4. Attempt to verify the original token against the payload with the tampered body
    const isValid = verifyAuthToken(
      tokenWithOriginalBody,
      payloadWithTamperedBody
    );

    // 5. Expect verification to FAIL
    expect(isValid).toBe(false);
  });

  it("should succeed verification if the body is correct", () => {
    const privateKeyWif = PrivateKey.fromRandom().toWif();
    const requestPath = "/api/data";
    const originalBody = JSON.stringify({ message: "original content" });

    const token = getAuthToken({
      privateKeyWif,
      requestPath,
      body: originalBody,
      scheme: "brc77",
    });

    const parsedToken = parseAuthToken(token);
    expect(parsedToken).not.toBeNull();
    if (!parsedToken) return;

    const payload: AuthPayload = {
      requestPath: parsedToken.requestPath,
      timestamp: parsedToken.timestamp,
      body: originalBody, // Correct body
    };

    const isValid = verifyAuthToken(token, payload);
    expect(isValid).toBe(true);
  });
}); 