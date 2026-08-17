export interface MessageEnvelope {
    version: string;
    senderDid: string;
    timestamp: number;
    nonce: string;
    payload: string;
    signature: string;
}
export interface EnvelopeValidationOptions {
    maxTimestampDriftMs?: number;
    nonceCache?: {
        has(nonce: string): boolean;
        add(nonce: string): void;
    };
}
/**
 * Creates a deterministic payload string to sign or verify.
 */
export declare function getSigningPayload(envelope: Omit<MessageEnvelope, 'signature'>): string;
/**
 * Creates and signs a new MessageEnvelope.
 * @param payload The domain-specific serialized data payload.
 * @param senderDid The originator's DID (did:daup:<publicKeyHex>).
 * @param privateKeyHex The Ed25519 private key in hex.
 * @param version The protocol version identifier (default '1.0.0').
 */
export declare function createEnvelope(payload: string, senderDid: string, privateKeyHex: string, version?: string): MessageEnvelope;
/**
 * Verifies a MessageEnvelope's signature, timestamp validity, and replay protection.
 * Returns true if valid, false if invalid.
 */
export declare function verifyEnvelope(envelope: MessageEnvelope, options?: EnvelopeValidationOptions): boolean;
