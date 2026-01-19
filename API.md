# API Reference

This document provides a detailed API reference for the `bitcoin-auth` library.

## Functions

### `getAuthToken(config: AuthConfig): string`

Generates a Bitcoin authentication token string.

**Parameters:**

*   `config: AuthConfig` - An object containing the configuration for token generation.

**Returns:**

*   `string` - The generated authentication token.

**Details:**

The token is a pipe-separated string with the format: `pubkey|scheme|timestamp|requestPath|signature`.

*   `pubkey`: The compressed public key derived from `privateKeyWif`.
*   `scheme`: The signing scheme used (`'brc77'` or `'bsm'`).
*   `timestamp`: The ISO8601 timestamp of when the token was generated (or a provided one, though not typical for `getAuthToken`).
*   `requestPath`: The full request path, including query parameters.
*   `signature`: The cryptographic signature.

    *   For `brc77`, signs: `requestPath|timestamp|bodyHash` (where `bodyHash` is `sha256(body)` if body is present, otherwise an empty string).
    *   For `bsm`, signs: `requestPath|timestamp|bodyHash` (where `bodyHash` is `sha256(body)` if body is present, otherwise an empty string).

### `verifyAuthToken(token: string, targetPayload: AuthPayload, timePad: number = 5, bodyEncoding: 'utf8' | 'hex' | 'base64' = 'utf8'): boolean`

Verifies an authentication token against a target payload.

**Parameters:**

*   `token: string` - The authentication token string to verify.
*   `targetPayload: AuthPayload` - An object representing the expected payload against which the token should be verified. This should be constructed on the server using the current request's details (ensure `targetPayload.timestamp` is the server's current time).
*   `timePad: number` (optional) - The allowed time skew between the token's timestamp and the server's current time, in minutes. Defaults to `5`.
*   `bodyEncoding: 'utf8' | 'hex' | 'base64'` (optional) - The encoding of the `targetPayload.body`. This must match the encoding used when the token was generated if the scheme is `brc77` (or `bsm`, as it now also includes `bodyHash`) and a body is present. Defaults to `'utf8'`.

**Returns:**

*   `boolean` - `true` if the token is valid and matches the target payload within the allowed time skew, `false` otherwise.

**Verification Steps:**

1.  Parses the token using `parseAuthToken`. If parsing fails, returns `false`.
2.  Checks if the `requestPath` in the token matches `targetPayload.requestPath`. If not, returns `false`.
3.  Checks if the `scheme` in the token is known (`'brc77'` or `'bsm'`). If not, returns `false`.
4.  Verifies the timestamp:
    *   Converts the token's timestamp and the server's current time (from `targetPayload.timestamp`) to Date objects.
    *   Checks if the absolute difference is within `timePad` (in minutes). If not, returns `false`.
5.  Reconstructs the message that was originally signed based on the token's `scheme` and the `targetPayload`. For both `brc77` and `bsm`, this is `requestPath|timestamp|bodyHash` (where `bodyHash` is `sha256(targetPayload.body)` using `bodyEncoding` if `targetPayload.body` is present, otherwise an empty string).
6.  Verifies the signature against the reconstructed message using the public key from the token. If signature verification fails, returns `false`.
7.  If all checks pass, returns `true`.

### `parseAuthToken(token: string): AuthToken | null`

Parses a token string into an `AuthToken` object.

**Parameters:**

*   `token: string` - The authentication token string.

**Returns:**

*   `AuthToken | null` - An `AuthToken` object if parsing is successful, or `null` if the token format is invalid.

## Types

### `AuthConfig`

Configuration object for `getAuthToken`.

```typescript
export interface AuthConfig {
  /** The private key in WIF (Wallet Import Format) used for signing. */
  privateKeyWif: string;

  /** The full request path, including any query parameters (e.g., "/api/users?id=123"). */
  requestPath: string;

  /** Optional request body string. If provided and scheme is 'brc77', its SHA256 hash is included in the signature. */
  body?: string;

  /**
   * The signing scheme to use.
   * 'brc77': Recommended. Signs timestamp, requestPath, and hash of the body.
   * 'bsm': Legacy Bitcoin Signed Message. Signs timestamp and requestPath.
   * @default 'brc77'
   */
  scheme?: 'brc77' | 'bsm';

  /**
   * The encoding of the `body` string, if provided.
   * Used for hashing the body in the 'brc77' scheme.
   * @default 'utf8'
   */
  bodyEncoding?: 'utf8' | 'hex' | 'base64';
}
```

### `AuthToken`

Represents a parsed authentication token. (Note: the `AuthToken` type as defined in `types.ts` also includes an optional `body` field, which is not directly part of the parsed token string format itself but is part of the extended `AuthPayload`.)

```typescript
export interface AuthToken {
  /** The compressed public key (hex string) derived from the private key. */
  pubkey: string;

  /** The signing scheme used ('brc77' or 'bsm'). */
  scheme: 'brc77' | 'bsm';

  /** The ISO8601 timestamp string from the token. */
  timestamp: string;

  /** The request path from the token. */
  requestPath: string;

  /** The signature (hex string). */
  signature: string;

  /** Optional request body string. While not part of the direct token string, it's part of the extended AuthPayload type. */
  body?: string;
}
```

### `AuthPayload`

Data structure used by `verifyAuthToken` to represent the expected values from the current request, against which the token is verified. Also represents the data components that are signed.

```typescript
export interface AuthPayload {
  /** The full request path, including query parameters (e.g., "/api/users?id=123"). */
  requestPath: string;

  /**
   * The ISO8601 timestamp string.
   * When generating a token, this is typically `new Date().toISOString()`.
   * When verifying a token, this should also be `new Date().toISOString()` on the server to compare against the token's timestamp.
   */
  timestamp: string;

  /**
   * Optional request body string.
   * If the token was generated with a body under the 'brc77' scheme, this MUST be provided and match the original body for verification to succeed.
   */
  body?: string;
}
``` 