/**
 * The structure of the message payload that is signed during auth token generation.
 * This is also the expected structure for the target payload when verifying a token.
 */
export interface AuthPayload {
  requestPath: string;
  timestamp: string; // ISO8601 format
  body?: string; // Optional request body string, to be hashed by the library
}

/**
 * The decoded structure of the final auth token payload
 */
export interface AuthToken extends AuthPayload {
  pubkey: string; // User's public key in hex format
  signature: string; // The signature string, base64 encoded
  scheme: 'bsm' | 'brc77'; // The scheme used to sign the payload
}

/**
 * The configuration for generating an authentication token.
 */
export interface AuthConfig {
  privateKeyWif: string;
  requestPath: string;
  body?: string;
  scheme?: 'bsm' | 'brc77';
  bodyEncoding?: 'hex' | 'base64' | 'utf8';
}
