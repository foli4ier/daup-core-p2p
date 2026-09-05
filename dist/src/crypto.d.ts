export interface KeyPairHex {
    publicKey: string;
    privateKey: string;
}
/**
 * Extract the 32-byte Ed25519 seed from a PKCS8 DER private key hex.
 * Does not log or return the full private key material beyond the seed bytes.
 */
export declare function ed25519SeedFromPkcs8Hex(privateKeyHex: string): Uint8Array;
/**
 * Generate a new Ed25519 key pair and return them in hex format.
 */
export declare function generateKeyPairHex(): KeyPairHex;
/**
 * Compute the Decentralized Identifier (DID) from a public key hex.
 */
export declare function getDidFromPublicKey(publicKeyHex: string): string;
/**
 * Extract the public key hex from a DID string.
 */
export declare function getPublicKeyFromDid(did: string): string;
/**
 * Sign data using an Ed25519 private key in hex.
 */
export declare function signData(data: string | Buffer, privateKeyHex: string): string;
/**
 * Verify a signature using an Ed25519 public key in hex.
 */
export declare function verifyData(data: string | Buffer, signatureHex: string, publicKeyHex: string): boolean;
