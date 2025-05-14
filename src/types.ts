/**
 * Represents the structure of the message payload that is signed during auth token generation.
 * This is also the expected structure for the target payload when verifying a token.
 */
export interface AuthPayload {
  requestPath: string;
  timestamp: string; // ISO8601 format
  body?: string; // Optional request body string, to be hashed by the library
}

/**
 * Represents the decoded structure of the final auth token payload
 */
export interface AuthToken extends AuthPayload {
  pubkey: string;    // User's public key in hex format
  signature: string; // The signature string, base64 encoded
} 