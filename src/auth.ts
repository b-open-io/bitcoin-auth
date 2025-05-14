import {
  BSM,
  Hash,
  PrivateKey,
  PublicKey,
  Signature,
  SignedMessage,
  Utils,
} from '@bsv/sdk';

import type { AuthPayload, AuthToken } from './types';

const { toBase64, toArray, toHex } = Utils;

/**
 * Generates an auth token for requests to the faucet API.
 *
 * @param privateKeyWif - The user's WIF-encoded private key.
 * @param requestPath - The full API endpoint path (e.g., /faucet/myfaucet/status).
 * @param body - Optional request body string to include in the signature.
 * @returns A promise that resolves to the Base64 encoded JSON string auth token.
 */
const getAuthTokenBSM = (
  privateKeyWif: string,
  requestPath: string,
  body?: string,
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8',
): string => {
  const privateKey = PrivateKey.fromWif(privateKeyWif);
  const pubkey = privateKey.toPublicKey().toString();
  const timestamp = new Date().toISOString();
  const bodyHash = body ? toHex(Hash.sha256(toArray(body, bodyEncoding))) : '';
  const message = `${requestPath}|${timestamp}|${bodyHash}`;
  const signature = BSM.sign(toArray(message), privateKey) as string;

  return `${pubkey}|bsm|${timestamp}|${requestPath}|${signature}`;
};

const getAuthTokenBRC77 = (
  privateKeyWif: string,
  requestPath: string,
  body?: string,
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8',
): string => {
  const privateKey = PrivateKey.fromWif(privateKeyWif);
  const pubkey = privateKey.toPublicKey().toString();
  const timestamp = new Date().toISOString();
  const bodyHash = body ? toHex(Hash.sha256(toArray(body, bodyEncoding))) : '';
  const message = toArray(`${requestPath}|${timestamp}|${bodyHash}`);
  const signature = toBase64(SignedMessage.sign(message, privateKey));
  return `${pubkey}|brc77|${timestamp}|${requestPath}|${signature}`;
};

const getAuthToken = (
  privateKeyWif: string,
  requestPath: string,
  scheme: 'bsm' | 'brc77' = 'brc77',
  body?: string,
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8',
): string => {
  if (scheme === 'bsm') {
    return getAuthTokenBSM(privateKeyWif, requestPath, body, bodyEncoding);
  }
  return getAuthTokenBRC77(privateKeyWif, requestPath, body, bodyEncoding);
};

/**
 * Verifies an authentication token against a target payload.
 *
 * @param token - The Base64 encoded authentication token string.
 * @param target - The target payload containing the request path, timestamp, and optional body we want to verify against.
 * @param timePad - The time padding in minutes. Defaults to 5 minutes.
 * @returns `true` if the token is valid, otherwise `false`.
 */
const verifyAuthTokenBSM = (
  parsedToken: AuthToken,
  target: AuthPayload,
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8',
): boolean => {
  const { pubkey, timestamp, requestPath, signature } = parsedToken;
  const bodyHash = target.body
    ? toHex(Hash.sha256(toArray(target.body, bodyEncoding)))
    : '';
  const message = `${requestPath}|${timestamp}|${bodyHash}`;
  const sig = Signature.fromCompact(signature, 'base64');
  const publicKey = PublicKey.fromString(pubkey);
  return BSM.verify(toArray(message), sig, publicKey);
};

/**
 * Parses a BSM token payload into a structured object.
 *
 * @param token - The Base64 encoded BSM token string.
 * @returns A structured object containing the parsed token payload.
 */
const parseAuthToken = (token: string): AuthToken | null => {
  const parts = token.split('|');
  if (parts.length !== 5) {
    return null; // Invalid structure
  }
  const [pubkey, scheme, timestamp, requestPath, signature] = parts;
  if (scheme !== 'bsm' && scheme !== 'brc77') {
    return null; // Invalid scheme
  }
  // Note: AuthToken in types.ts should include all these fields, including scheme
  return {
    pubkey,
    scheme,
    timestamp,
    requestPath,
    signature,
  };
};

const verifyPreRequisites = (
  parsedToken: AuthToken,
  target: AuthPayload,
  timePad = 5,
): boolean => {
  const payloadTimestamp = new Date(parsedToken.timestamp);
  const targetTime = new Date(target.timestamp);
  targetTime.setMinutes(targetTime.getMinutes() + timePad);
  if (payloadTimestamp > targetTime) {
    return false;
  }
  if (parsedToken.requestPath !== target.requestPath) {
    return false;
  }

  try {
    const publicKey = PublicKey.fromString(parsedToken.pubkey);
    if (!publicKey) {
      return false;
    }
  } catch (error) {
    return false;
  }
  return true;
};

const verifyAuthToken = (
  token: string,
  target: AuthPayload,
  timePad = 5,
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8',
): boolean => {
  const parsedToken = parseAuthToken(token);
  if (!parsedToken) {
    return false; // Token is malformed or has an invalid scheme
  }

  if (!verifyPreRequisites(parsedToken, target, timePad)) {
    return false;
  }

  if (parsedToken.scheme === 'bsm') {
    return verifyAuthTokenBSM(parsedToken, target, bodyEncoding);
  }

  // If not 'bsm', it must be 'brc77' due to parseAuthToken validation
  return verifyAuthTokenBRC77(parsedToken, target, bodyEncoding);
};

const verifyAuthTokenBRC77 = (
  parsedToken: AuthToken,
  target: AuthPayload,
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8',
): boolean => {
  const { timestamp, requestPath, signature } = parsedToken;
  const bodyHash = target.body
    ? toHex(Hash.sha256(toArray(target.body, bodyEncoding)))
    : '';
  const messageToVerify = toArray(`${requestPath}|${timestamp}|${bodyHash}`);
  return SignedMessage.verify(messageToVerify, toArray(signature, 'base64'));
};

export {
  getAuthToken,
  verifyAuthToken,
  getAuthTokenBSM,
  verifyAuthTokenBSM,
  getAuthTokenBRC77,
  verifyAuthTokenBRC77,
  parseAuthToken,
};
