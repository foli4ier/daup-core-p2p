import { generateKeyPairSync, createPublicKey, createPrivateKey, sign, verify } from 'node:crypto';

export interface KeyPairHex {
  publicKey: string;  // hex format of SPKI DER
  privateKey: string; // hex format of PKCS8 DER
}

/**
 * Generate a new Ed25519 key pair and return them in hex format.
 */
export function generateKeyPairHex(): KeyPairHex {
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
export function getDidFromPublicKey(publicKeyHex: string): string {
  return `did:daup:${publicKeyHex}`;
}

/**
 * Extract the public key hex from a DID string.
 */
export function getPublicKeyFromDid(did: string): string {
  if (!did.startsWith('did:daup:')) {
    throw new Error(`Invalid DID scheme: ${did}`);
  }
  return did.split(':')[2];
}

/**
 * Sign data using an Ed25519 private key in hex.
 */
export function signData(data: string | Buffer, privateKeyHex: string): string {
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
export function verifyData(data: string | Buffer, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyHex, 'hex'),
      format: 'der',
      type: 'spki'
    });
    
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    const signatureBuffer = Buffer.from(signatureHex, 'hex');
    
    return verify(null, dataBuffer, publicKey, signatureBuffer);
  } catch (err) {
    return false;
  }
}
