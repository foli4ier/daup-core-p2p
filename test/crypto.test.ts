import { describe, it, expect } from 'vitest';
import { generateKeyPairHex, getDidFromPublicKey, getPublicKeyFromDid, signData, verifyData } from '../src/crypto.js';

describe('Cryptography Module', () => {
  it('should generate valid Ed25519 hex key pairs', () => {
    const keys = generateKeyPairHex();
    expect(keys.publicKey).toBeTypeOf('string');
    expect(keys.privateKey).toBeTypeOf('string');
    expect(keys.publicKey.length).toBeGreaterThan(0);
    expect(keys.privateKey.length).toBeGreaterThan(0);
  });

  it('should map public key to did and extract it back', () => {
    const keys = generateKeyPairHex();
    const did = getDidFromPublicKey(keys.publicKey);
    expect(did).toBe(`did:daup:${keys.publicKey}`);

    const extracted = getPublicKeyFromDid(did);
    expect(extracted).toBe(keys.publicKey);
  });

  it('should sign data and verify successfully', () => {
    const keys = generateKeyPairHex();
    const data = 'test-payload';
    const signature = signData(data, keys.privateKey);

    expect(signature).toBeTypeOf('string');
    expect(signature.length).toBeGreaterThan(0);

    const isValid = verifyData(data, signature, keys.publicKey);
    expect(isValid).toBe(true);
  });

  it('should reject signature verification for tampered data', () => {
    const keys = generateKeyPairHex();
    const data = 'test-payload';
    const signature = signData(data, keys.privateKey);

    const isValid = verifyData('tampered-payload', signature, keys.publicKey);
    expect(isValid).toBe(false);
  });

  it('should reject signature verification for tampered signature', () => {
    const keys = generateKeyPairHex();
    const data = 'test-payload';
    const signature = signData(data, keys.privateKey);
    const tamperedSig = signature.replace(/^[0-9a-f]/i, 'g'); // invalid hex char

    const isValid = verifyData(data, tamperedSig, keys.publicKey);
    expect(isValid).toBe(false);
  });
});
