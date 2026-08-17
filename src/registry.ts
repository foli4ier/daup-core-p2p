import { getPublicKeyFromDid } from './crypto.js';

export interface DidDocument {
  '@context': string;
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyHex: string;
  }>;
}

/**
 * Publishes a DID Document to the Kademlia DHT.
 */
export async function publishDidDocument(
  node: any,
  did: string,
  publicKeyHex: string
): Promise<void> {
  const dht = node.services.dht;
  if (!dht) {
    throw new Error('Kademlia DHT service is not enabled on this node');
  }

  const doc: DidDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    verificationMethod: [
      {
        id: `${did}#keys-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyHex
      }
    ]
  };

  const keyText = `/dids/${did}`;
  const keyBytes = new TextEncoder().encode(keyText);
  const valueBytes = new TextEncoder().encode(JSON.stringify(doc));

  for await (const _ of dht.put(keyBytes, valueBytes)) {}
}

/**
 * Resolves a DID Document from the Kademlia DHT.
 */
export async function resolveDidDocument(
  node: any,
  did: string
): Promise<DidDocument | null> {
  const dht = node.services.dht;
  if (!dht) {
    throw new Error('Kademlia DHT service is not enabled on this node');
  }

  const keyText = `/dids/${did}`;
  const keyBytes = new TextEncoder().encode(keyText);

  try {
    const events = dht.get(keyBytes);
    for await (const event of events) {
      // Check if this is a value event containing our content
      if ('value' in event && event.value !== undefined) {
        const text = new TextDecoder().decode(event.value);
        return JSON.parse(text) as DidDocument;
      }
    }
  } catch (err) {
    // If not found in DHT, or query errors, return null
  }

  return null;
}
