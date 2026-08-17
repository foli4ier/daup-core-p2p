import { describe, it, expect } from 'vitest';
import { generateKeyPairHex, getDidFromPublicKey, signData } from '../src/crypto.js';
import { createEnvelope, verifyEnvelope, getSigningPayload } from '../src/envelope.js';
describe('Message Envelope Module', () => {
    it('should create and verify valid envelopes', () => {
        const keys = generateKeyPairHex();
        const did = getDidFromPublicKey(keys.publicKey);
        const payload = JSON.stringify({ event: 'ping', data: 42 });
        const envelope = createEnvelope(payload, did, keys.privateKey);
        expect(envelope.version).toBe('1.0.0');
        expect(envelope.senderDid).toBe(did);
        expect(envelope.payload).toBe(payload);
        expect(envelope.signature).toBeTypeOf('string');
        const isValid = verifyEnvelope(envelope);
        expect(isValid).toBe(true);
    });
    it('should fail validation if envelope payload is tampered', () => {
        const keys = generateKeyPairHex();
        const did = getDidFromPublicKey(keys.publicKey);
        const envelope = createEnvelope('hello', did, keys.privateKey);
        // Tamper payload
        envelope.payload = 'tampered';
        const isValid = verifyEnvelope(envelope);
        expect(isValid).toBe(false);
    });
    it('should fail validation if envelope timestamp drifts beyond allowed window', () => {
        const keys = generateKeyPairHex();
        const did = getDidFromPublicKey(keys.publicKey);
        const envelope = createEnvelope('hello', did, keys.privateKey);
        // Backdate timestamp by 10 minutes (default max drift is 5 minutes)
        envelope.timestamp = Date.now() - 10 * 60 * 1000;
        // Resign the envelope to bypass signature check but fail drift check
        const signingPayload = getSigningPayload(envelope);
        envelope.signature = signData(signingPayload, keys.privateKey);
        const isValid = verifyEnvelope(envelope, { maxTimestampDriftMs: 5 * 60 * 1000 });
        expect(isValid).toBe(false);
    });
    it('should enforce replay protection using nonce cache', () => {
        const keys = generateKeyPairHex();
        const did = getDidFromPublicKey(keys.publicKey);
        const envelope = createEnvelope('hello', did, keys.privateKey);
        const seenNonces = new Set();
        const nonceCache = {
            has: (nonce) => seenNonces.has(nonce),
            add: (nonce) => seenNonces.add(nonce)
        };
        // First verification should pass and cache the nonce
        const isValid1 = verifyEnvelope(envelope, { nonceCache });
        expect(isValid1).toBe(true);
        expect(seenNonces.has(envelope.nonce)).toBe(true);
        // Second verification with same envelope should fail (replay)
        const isValid2 = verifyEnvelope(envelope, { nonceCache });
        expect(isValid2).toBe(false);
    });
});
