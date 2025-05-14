# Bitcoin Auth

[![npm version](https://badge.fury.io/js/bitcoin-auth.svg)](https://badge.fury.io/js/bitcoin-auth)
[![npm downloads](https://img.shields.io/npm/dm/bitcoin-auth.svg)](https://www.npmjs.com/package/bitcoin-auth)

The "Bitcoin Auth" library simplifies authenticating REST APIs with Bitcoin keys by generating and verifying cryptographic signatures in an `X-Auth-Token` header.

## Installation

Install with Bun:

```bash
bun add bitcoin-auth
```

## Generating an Auth Token

```typescript
import { getAuthToken } from 'bitcoin-auth';

// Generate the token
const token = getAuthToken(privateKeyWif, path, body, 'brc77');
```

```typescript
console.log({ token });
// Output: { token: "pubkey|scheme|timestamp|requestPath|signature" }
```

```typescript
// Include the token in your API request:
const response = await fetch("https://somedomain.com" + path, {
  method: 'POST',
  headers: { 'X-Auth-Token': token },
  body
});
```

When your request includes a body, provide it:

```typescript
const tokenWithBody = getAuthToken(privateKeyWif, apiPath, body, 'brc77');
```

For classic Bitcoin Signed Message:

```typescript
const tokenNoBodyBsm = getAuthToken(privateKeyWif, apiPath, body, 'bsm');
```

## Features

* **Auth Token Generation & Verification**: Easy-to-use functions for token handling.
* **Dual Cryptographic Schemes**: Supports 'bsm' (legacy) and 'brc77' (modern, [BRC-77](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md)).
* **Minimal Dependencies**: Only requires the peer dependency `@bsv/sdk`.

## Usage Details

Tokens contain:

* Request path (including query parameters)
* ISO8601 timestamp
* SHA256 hash of request body (if present)
* Signing scheme used ('bsm' or 'brc77')

Token format:
`pubkey|scheme|timestamp|requestPath|signature`

Cryptographic schemes:

* `'brc77'` (default): Recommended scheme, uses `SignedMessage.sign()` from BSV SDK.
* `'bsm'`: Classic Bitcoin Signed Message via `BSM.sign()` from BSV SDK.

### Token Generation Example

```typescript
import { getAuthToken, parseAuthToken, verifyAuthToken, AuthToken, AuthPayload } from 'bitcoin-auth';
import { PrivateKey } from "@bsv/sdk";

const privateKey = PrivateKey.fromRandom();
const path = "/some/api/path?param1=value1";
const body = JSON.stringify(["hello", "world"]);

const tokenWithBody = getAuthToken(privateKeyWif, path, body, 'brc77');
const tokenNoBodyBsm = getAuthToken(privateKeyWif, path, undefined, 'bsm');
```

## Parsing & Verification

Parsing a token:

```typescript
const parsedToken: AuthToken | null = parseAuthToken(tokenWithBody);
if (parsedToken) {
  console.log(parsedToken);
} else {
  console.log("Failed to parse token.");
}
```

Verifying tokens:

```typescript
const authPayload: AuthPayload = {
  requestPath,
  timestamp: new Date().toISOString(),
  body
};

const isValid = verifyAuthToken(tokenWithBody, authPayload);

const payloadNoBody: AuthPayload = {
  requestPath,
  timestamp: new Date().toISOString()
};

const isValidNoBody = verifyAuthToken(tokenNoBodyBsm, payloadNoBody);
```

**Security Note**: Always securely handle `privateKeyWif`.

### Types and Interfaces

Core authentication types:

* `AuthToken`: `{ pubkey, scheme, timestamp, requestPath, signature }`
* `AuthPayload`: Data for signing/verification:

```typescript
export interface AuthPayload {
  requestPath: string;
  timestamp: string; // ISO8601
  body?: string;
}
```

Example:

```typescript
const payloadWithBody: AuthPayload = {
  requestPath: '/api/items',
  timestamp: new Date().toISOString(),
  body: JSON.stringify({ name: "gadget", price: 9.99 })
};

const payload: AuthPayload = {
  requestPath: '/api/items/123',
  timestamp: new Date().toISOString()
};
```

### API Reference

#### `getAuthToken(privateKeyWif, requestPath, body?, scheme?, bodyEncoding?)`

Generates a token:

* `privateKeyWif`: WIF format private key
* `requestPath`: Full request URL path
* `body`: Optional request body
* `scheme`: Optional signing scheme (`'brc77'` or `'bsm'`, default `'brc77'`)
* `bodyEncoding`: Optional encoding (default `'utf8'`)

Returns token as a string.

#### `verifyAuthToken(token, target, timePad?, bodyEncoding?)`

Verifies a token:

* `token`: Token string
* `target`: Expected `AuthPayload`
* `timePad`: Optional allowed time skew in minutes (default `5`)
* `bodyEncoding`: Optional body encoding (default `'utf8'`)

Returns boolean indicating validity.

#### `parseAuthToken(token)`

Parses token into `AuthToken` or returns `null`.

## Development

Use Bun to build and test:

```bash
bun run build
bun test
```
