# Bitcoin Auth

[![npm version](https://badge.fury.io/js/bitcoin-auth.svg)](https://badge.fury.io/js/bitcoin-auth)
[![npm downloads](https://img.shields.io/npm/dm/bitcoin-auth.svg)](https://www.npmjs.com/package/bitcoin-auth)

The "Bitcoin Auth" client library provides an easy way to authenticate users with REST APIs using private keys via signatures. This library simplifies generating and verifying an `X-Auth-Token` header containing a cryptographic signature.


## Installation

```bash
bun add bitcoin-auth
```

## Generating an Auth Token

To create an `X-Auth-Token`:

Import the auth helper
```typescript
import { getAuthToken } from 'bitcoin-auth';
```

Generate the token, providing the wif, path, and body.

```typescript
const token = getAuthToken(privateKeyWif, path, body);
console.log({ token })
// { token: "pubkey|timestamp|requestPath|signature" }
```

Add the `X-Auth-Token` header to your API request:

```typescript
const response = await fetch("https://somedomain.com/", {
  method: 'POST',
  headers: { 'X-Auth-Token': token },
  body
});
```

## Features

* **Auth Token Generation & Verification**: Easy-to-use functions for generating and verifying `X-Auth-Token` headers.
* **Dual Cryptographic Modes**: Supports classic 'bsm' and modern 'bsv' [(BRC-77)](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md) signing modes.
* **Zero Direct Dependencies**: Peer dependency of `@bsv/sdk` which itself has zero dependecies.

## Usage Details

Authentication involves creating a token from the request path, a timestamp, and when a body is part of the request you also sign the SHA256 hash of the request body. Two cryptographic modes are supported:

* Classic 'bsm' mode uses [Bitcoin Signed Message](https://en.bitcoin.it/wiki/Message_signing)
* Modern 'bsv' mode compliant with [BRC-77](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md).

### Token Generation

```typescript
import { getAuthToken, parseAuthToken, verifyAuthToken, AuthToken, AuthPayload } from 'bitcoin-auth';
```

Use ANY Bitcoin library to generate a key in WIF format
```typescript
import { PrivateKey } from "@bsv/sdk";
const privateKey = PrivateKey.fromRandom();
```

Prepare the path and body
```typescript
const path = "/some/api/path";
const body = JSON.stringify(["hello", "world"]);
```

When making a request with a body, be sure to provide it to the auth function.
```typescript
const tokenWithBody = getAuthToken(privateKeyWif, apiPath, httpRequestBody);
```

// To sign using Bitcoin Signed Message (classic) instead...
```typescript
const tokenNoBodyBsm = getAuthToken(privateKeyWif, apiPath, 'bsm');
```

## Parsing & Verification

```typescript
const { pubkey, timestamp, requestPath, signature }: AuthToken = parseAuthToken(tokenWithBody);
console.log({ pubkey, timestamp, requestPath, signature });
// Prints
// { pubkey: '...', timestamp: '...', requestPath: '...', signature: '...' }
```

```typescript
// Verification example with body
const payload: AuthPayload = {
  timestamp: new Date().toISOString(),
  requestPath,
  body,
};
// For bodies that are not UTF-8 strings, you can specify encoding e.g. 'hex' or 'base64' as the last argument to verifyAuthToken.
const isValidWith = verifyAuthToken(tokenWithBody, payload);

// Verification example without body
const verificationPayloadNoBody: AuthPayload = {
  requestPath: apiPath,
  timestamp: new Date().toISOString()
};
const isValidNoBody = verifyAuthToken(tokenNoBodyBsm, verificationPayloadNoBody, 5, 'bsm');
```

**Important Security Note**: Handle the `privateKeyWif` securely at all times.

### DTOs and Auth Types

Core authentication interfaces:

* `AuthToken`: Represents the fields extracted by `parseAuthToken` from the token string: `{ pubkey, timestamp, requestPath, signature }`. The type also inherits `body?: string` from `AuthPayload`.
* `AuthPayload`: Data required for signing/verification:

```typescript
export interface AuthPayload {
  requestPath: string;
  timestamp: string; // ISO8601 format
  body?: string;     // Optional, required if used during token generation
}
```

Example construction:

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

### Signature Format

* **Both BSM and BSV (BRC-77) signatures are base64-encoded.**

## Tests

Run tests:

```bash
bun test
```

Tests cover both signing modes and optional body hashing.

## Development

Uses Bun for development tasks:

* **Build**: `bun run build`
* **Test**: `bun test`

