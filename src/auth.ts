import { PrivateKey, BSM, Utils, Signature, PublicKey, SignedMessage, Hash } from '@bsv/sdk'

import type { AuthPayload, AuthToken } from './types';

const { toBase64, toArray, toHex } = Utils

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
  bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8'
): string => {
  const privateKey = PrivateKey.fromWif(privateKeyWif)
  const pubkey = privateKey.toPublicKey().toString()
  const timestamp = new Date().toISOString()
  const bodyHash = body ? toHex(Hash.sha256(toArray(body, bodyEncoding))) : '';
  const message = `${requestPath}|${timestamp}|${bodyHash}`
  const signature = BSM.sign(toArray(message), privateKey) as string;

  return `${pubkey}|${timestamp}|${requestPath}|${signature}`
}

/**
 * Verifies an authentication token against a target payload.
 *
 * @param token - The Base64 encoded authentication token string.
 * @param target - The target payload containing the request path, timestamp, and optional body we want to verify against.
 * @param timePad - The time padding in minutes. Defaults to 5 minutes.
 * @returns `true` if the token is valid, otherwise `false`.
 */
const verifyAuthTokenBSM = (token: string, target: AuthPayload, timePad = 5, bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8'): boolean => {
  const [pubkey, timestamp, requestPath, signature] = token.split('|')
  const payloadTimestamp = new Date(timestamp)
  const targetTime = new Date(target.timestamp)
  targetTime.setMinutes(targetTime.getMinutes() + timePad)
  if (payloadTimestamp > targetTime) {
    return false
  }
  if (requestPath !== target.requestPath) {
    return false
  }
  const bodyHash = target.body ? toHex(Hash.sha256(toArray(target.body, bodyEncoding))) : '';
  const message = `${requestPath}|${timestamp}|${bodyHash}`
  const sig = Signature.fromCompact(signature, 'base64')
  const publicKey = PublicKey.fromString(pubkey)
  return BSM.verify(toArray(message), sig, publicKey)
}

/**
 * Parses a BSM token payload into a structured object.
 *
 * @param token - The Base64 encoded BSM token string.
 * @returns A structured object containing the parsed token payload.
 */
const parseAuthToken = (token: string): AuthToken => {
  const [pubkey, timestamp, requestPath, signature] = token.split('|')
  return { pubkey, timestamp, requestPath, signature }
}

const getAuthTokenBSV = (privateKeyWif: string, requestPath: string, body?: string): string => {
  const privateKey = PrivateKey.fromWif(privateKeyWif)
  const pubkey = privateKey.toPublicKey().toString()
  const timestamp = new Date().toISOString()
  const bodyHash = body ? toHex(Hash.sha256(toArray(body))) : '';
  const message = toArray(`${requestPath}|${timestamp}|${bodyHash}`)
  const signature = toBase64(SignedMessage.sign(message, privateKey))
  return `${pubkey}|${timestamp}|${requestPath}|${signature}`
}

const getAuthToken = (privateKeyWif: string, requestPath: string, mode: 'bsm' | 'bsv' = 'bsv', body?: string, bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8'): string => {
  if (mode === 'bsm') {
    return getAuthTokenBSM(privateKeyWif, requestPath, body, bodyEncoding)
  }
  return getAuthTokenBSV(privateKeyWif, requestPath, body)
}

const verifyAuthToken = (token: string, target: AuthPayload, timePad = 5, mode: 'bsm' | 'bsv' = 'bsv', bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8'): boolean => {
  if (!verifyPreRequisites(token, target, timePad)) {
    return false
  }
  if (mode === 'bsm') {
    return verifyAuthTokenBSM(token, target, timePad, bodyEncoding)
  }
  return verifyAuthTokenBSV(token, target, timePad, bodyEncoding)
}

const verifyAuthTokenBSV = (token: string, target: AuthPayload, timePad = 5, bodyEncoding: 'hex' | 'base64' | 'utf8' = 'utf8'): boolean => {
  const [_, timestamp, requestPath, signature] = token.split('|')
  const bodyHash = target.body ? toHex(Hash.sha256(toArray(target.body, bodyEncoding))) : '';
  const messageToVerify = toArray(`${requestPath}|${timestamp}|${bodyHash}`)
  return SignedMessage.verify(messageToVerify, toArray(signature, 'base64'))
}

const verifyPreRequisites = (token: string, target: AuthPayload, timePad = 5): boolean => {
  const [pubkey, timestamp, requestPath, signature] = token.split('|')

  if (!pubkey || !timestamp || !requestPath || !signature) {
    return false;
  }

  const payloadTimestamp = new Date(timestamp)
  const targetTime = new Date(target.timestamp)
  targetTime.setMinutes(targetTime.getMinutes() + timePad)
  if (payloadTimestamp > targetTime) {
    return false
  }
  if (requestPath !== target.requestPath) {
    return false
  }

  try {
    const publicKey = PublicKey.fromString(pubkey)
    if (!publicKey) {
      return false
    }
  } catch (error) {
    return false
  }
  return true
}

export {
  getAuthToken,
  verifyAuthToken,
  getAuthTokenBSM,
  verifyAuthTokenBSM,
  getAuthTokenBSV,
  verifyAuthTokenBSV,
  parseAuthToken
}