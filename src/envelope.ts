import { randomBytes } from 'node:crypto';
import { getPublicKeyFromDid, signData, verifyData } from './crypto.js';

export interface MessageEnvelope {
  version: string;
  senderDid: string;
  timestamp: number; // Unix epoch timestamp in milliseconds
  nonce: string;     // Unique identifier for replay protection
  payload: string;   // Domain-specific data body (serialized or encoded)
  signature: string; // Cryptographic signature of the serialized envelope fields
}

export interface EnvelopeValidationOptions {
  maxTimestampDriftMs?: number; // Maximum allowed time drift in milliseconds (default 5 mins)
  nonceCache?: {
    has(nonce: string): boolean;
    add(nonce: string): void;
  };
}

/**
 * Creates a deterministic payload string to sign or verify.
 */
export function getSigningPayload(envelope: Omit<MessageEnvelope, 'signature'>): string {
  return [
    envelope.version,
    envelope.senderDid,
    envelope.timestamp.toString(),
    envelope.nonce,
    envelope.payload
  ].join('|');
}

/**
 * Creates and signs a new MessageEnvelope.
 * @param payload The domain-specific serialized data payload.
 * @param senderDid The originator's DID (did:daup:<publicKeyHex>).
 * @param privateKeyHex The Ed25519 private key in hex.
 * @param version The protocol version identifier (default '1.0.0').
 */
export function createEnvelope(
  payload: string,
  senderDid: string,
  privateKeyHex: string,
  version: string = '1.0.0'
): MessageEnvelope {
  const envelope: Omit<MessageEnvelope, 'signature'> = {
    version,
    senderDid,
    timestamp: Date.now(),
    nonce: randomBytes(16).toString('hex'),
    payload
  };

  const signingPayload = getSigningPayload(envelope);
  const signature = signData(signingPayload, privateKeyHex);

  return {
    ...envelope,
    signature
  };
}

/**
 * Verifies a MessageEnvelope's signature, timestamp validity, and replay protection.
 * Returns true if valid, false if invalid.
 */
export function verifyEnvelope(
  envelope: MessageEnvelope,
  options: EnvelopeValidationOptions = {}
): boolean {
  try {
    const {
      maxTimestampDriftMs = 5 * 60 * 1000, // 5 minutes default
      nonceCache
    } = options;

    // 1. Validate DID scheme and extract public key
    const publicKeyHex = getPublicKeyFromDid(envelope.senderDid);
    if (!publicKeyHex) return false;

    // 2. Verify signature
    const signingPayload = getSigningPayload(envelope);
    const isValidSignature = verifyData(signingPayload, envelope.signature, publicKeyHex);
    if (!isValidSignature) return false;

    // 3. Verify timestamp drift
    const now = Date.now();
    const drift = Math.abs(now - envelope.timestamp);
    if (drift > maxTimestampDriftMs) {
      return false; // Expired or future timestamp
    }

    // 4. Verify replay protection (nonce cache)
    if (nonceCache) {
      if (nonceCache.has(envelope.nonce)) {
        return false; // Replay attack detected
      }
      nonceCache.add(envelope.nonce);
    }

    return true;
  } catch (err) {
    return false;
  }
}
