import { generateKeyPairSync, createPublicKey, createPrivateKey, sign, verify } from 'node:crypto';
/**
 * Extract the 32-byte Ed25519 seed from a PKCS8 DER private key hex.
 * Does not log or return the full private key material beyond the seed bytes.
 */
export function ed25519SeedFromPkcs8Hex(privateKeyHex) {
    const privateKey = createPrivateKey({
        key: Buffer.from(privateKeyHex, 'hex'),
        format: 'der',
        type: 'pkcs8'
    });
    const jwk = privateKey.export({ format: 'jwk' });
    if (!jwk.d) {
        throw new Error('Invalid peer private key: Ed25519 seed missing');
    }
    const seed = Buffer.from(jwk.d, 'base64url');
    if (seed.length !== 32) {
        throw new Error('Invalid peer private key: Ed25519 seed must be 32 bytes');
    }
    return seed;
}
/**
 * Generate a new Ed25519 key pair and return them in hex format.
 */
export function generateKeyPairHex() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicKeyHex = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
    const privateKeyHex = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
    return {
        publicKey: publicKeyHex,
        privateKey: privateKeyHex
    };
}
/**
 * Compute the Decentralized Identifier (DID) from a public key hex.
 */
export function getDidFromPublicKey(publicKeyHex) {
    return `did:daup:${publicKeyHex}`;
}
/**
 * Extract the public key hex from a DID string.
 */
export function getPublicKeyFromDid(did) {
    if (!did.startsWith('did:daup:')) {
        throw new Error(`Invalid DID scheme: ${did}`);
    }
    return did.split(':')[2];
}
/**
 * Sign data using an Ed25519 private key in hex.
 */
export function signData(data, privateKeyHex) {
    const privateKey = createPrivateKey({
        key: Buffer.from(privateKeyHex, 'hex'),
        format: 'der',
        type: 'pkcs8'
    });
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    const signature = sign(null, dataBuffer, privateKey);
    return signature.toString('hex');
}
/**
 * Verify a signature using an Ed25519 public key in hex.
 */
export function verifyData(data, signatureHex, publicKeyHex) {
    try {
        const publicKey = createPublicKey({
            key: Buffer.from(publicKeyHex, 'hex'),
            format: 'der',
            type: 'spki'
        });
        const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
        const signatureBuffer = Buffer.from(signatureHex, 'hex');
        return verify(null, dataBuffer, publicKey, signatureBuffer);
    }
    catch (err) {
        return false;
    }
}
