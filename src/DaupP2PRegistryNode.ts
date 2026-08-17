import { P2PNode } from './node.js';
import { MessageEnvelope } from './envelope.js';
import { getPublicKeyFromDid, signData, verifyData } from './crypto.js';
import { publishDidDocument, resolveDidDocument } from './registry.js';

/**
 * Interface representing a decentralized application manifest.
 */
export interface AppManifest {
  appId: string;           // Unique identifier for the app, e.g., 'daup-farmer'
  version: string;         // Semantic version string, e.g., '1.2.0'
  name: string;            // Human-readable application name
  description: string;     // Short description of the application
  icon?: string;           // Optional base64 encoded application icon or image URI
  wasmBinaryHash: string;  // Cryptographic hash (SHA-256 / CID) of the WebAssembly executable
  wasmBinaryUrl?: string;  // Optional remote download URL for the WebAssembly package
  versionHash: string;     // Unique cryptographic hash representing this specific release version
  publisherDid: string;    // DID of the publisher (did:daup:<publicKeyHex>)
  timestamp: number;       // Unix epoch timestamp in milliseconds
  signature?: string;      // Optional Ed25519 signature of the manifest fields by the publisher
}

/**
 * Construct a deterministic payload string for signing or verifying an AppManifest.
 */
export function getAppManifestSigningPayload(manifest: Omit<AppManifest, 'signature'>): string {
  return [
    manifest.appId,
    manifest.version,
    manifest.name,
    manifest.description,
    manifest.icon || '',
    manifest.wasmBinaryHash,
    manifest.wasmBinaryUrl || '',
    manifest.versionHash,
    manifest.publisherDid,
    manifest.timestamp.toString()
  ].join('|');
}

/**
 * Helper to cryptographically sign an AppManifest using an Ed25519 private key.
 */
export function signAppManifest(
  manifest: Omit<AppManifest, 'signature'>,
  privateKeyHex: string
): AppManifest {
  const signingPayload = getAppManifestSigningPayload(manifest);
  const signature = signData(signingPayload, privateKeyHex);
  return {
    ...manifest,
    signature
  };
}

/**
 * Helper to cryptographically verify an AppManifest's publisher signature.
 */
export function verifyAppManifestSignature(manifest: AppManifest): boolean {
  if (!manifest.signature) return false;
  try {
    const publicKeyHex = getPublicKeyFromDid(manifest.publisherDid);
    const signingPayload = getAppManifestSigningPayload(manifest);
    return verifyData(signingPayload, manifest.signature, publicKeyHex);
  } catch (err) {
    return false;
  }
}

/**
 * Specialized P2P registry node for the DAUP ecosystem.
 * Extends the baseline P2PNode to enable Kademlia DHT queries and pubsub broadcasts.
 */
export class DaupP2PRegistryNode extends P2PNode {
  
  /**
   * Publishes an application manifest to the Kademlia DHT.
   * Writes the manifest under both the App ID and the specific Version Hash.
   */
  async publishAppManifest(manifest: AppManifest): Promise<void> {
    if (!this.node) {
      throw new Error('P2P node is not started');
    }

    const dht = this.node.services.dht;
    if (!dht) {
      throw new Error('Kademlia DHT service is not enabled on this node');
    }

    // If a signature is present, validate it before publishing to the network
    if (manifest.signature) {
      const isValid = verifyAppManifestSignature(manifest);
      if (!isValid) {
        throw new Error('AppManifest signature verification failed; publish aborted');
      }
    }

    const serialized = JSON.stringify(manifest);
    const valueBytes = new TextEncoder().encode(serialized);

    // 1. Put under /apps/appId (representing current/latest track)
    const keyAppId = new TextEncoder().encode(`/apps/${manifest.appId}`);
    for await (const _ of dht.put(keyAppId, valueBytes)) {}

    // 2. Put under /apps/versionHash (representing immutable specific version)
    const keyVersionHash = new TextEncoder().encode(`/apps/${manifest.versionHash}`);
    for await (const _ of dht.put(keyVersionHash, valueBytes)) {}
  }

  /**
   * Retrieves and parses an AppManifest from Kademlia DHT.
   * @param cidOrKey The key to query, which can be an App ID, Version Hash, or fully qualified path.
   */
  async fetchAppManifest(cidOrKey: string): Promise<AppManifest | null> {
    if (!this.node) {
      throw new Error('P2P node is not started');
    }

    const dht = this.node.services.dht;
    if (!dht) {
      throw new Error('Kademlia DHT service is not enabled on this node');
    }

    const keyPath = cidOrKey.startsWith('/') ? cidOrKey : `/apps/${cidOrKey}`;
    const keyBytes = new TextEncoder().encode(keyPath);

    try {
      const events = dht.get(keyBytes);
      for await (const event of events) {
        if ('value' in event && event.value !== undefined) {
          const text = new TextDecoder().decode(event.value);
          const manifest = JSON.parse(text) as AppManifest;
          return manifest;
        }
      }
    } catch (err: any) {
      console.warn(`[RegistryNode] Failed to fetch manifest for key '${keyPath}':`, err.message);
    }

    return null;
  }

  /**
   * Broadcasts a new application release event to all connected peers via Gossipsub.
   */
  async broadcastAppRelease(manifest: AppManifest): Promise<void> {
    const payload = JSON.stringify(manifest);
    await this.publishMessage('daup:app:releases', payload);
  }

  /**
   * Broadcasts a subscription renewal event to all connected peers via Gossipsub.
   */
  async broadcastSubscriptionRenewal(renewal: any): Promise<void> {
    const payload = JSON.stringify(renewal);
    await this.publishMessage('daup:subscriptions:renewals', payload);
  }

  /**
   * Registers a listener to intercept real-time application release broadcasts.
   */
  subscribeToReleases(
    onRelease: (manifest: AppManifest, envelope: MessageEnvelope) => void
  ): void {
    this.subscribeToTopic('daup:app:releases', (payload, envelope) => {
      try {
        const manifest = JSON.parse(payload) as AppManifest;
        onRelease(manifest, envelope);
      } catch (err: any) {
        console.error('[RegistryNode] Failed to parse broadcast app release payload:', err.message);
      }
    });
  }

  /**
   * Registers a listener to intercept real-time subscription renewal broadcasts.
   */
  subscribeToRenewals(
    onRenewal: (renewal: any, envelope: MessageEnvelope) => void
  ): void {
    this.subscribeToTopic('daup:subscriptions:renewals', (payload, envelope) => {
      try {
        const renewal = JSON.parse(payload);
        onRenewal(renewal, envelope);
      } catch (err: any) {
        console.error('[RegistryNode] Failed to parse broadcast subscription renewal payload:', err.message);
      }
    });
  }

  /**
   * Gateway hook: Looks up a user's DID Document from the Kademlia DHT.
   */
  async lookupDidDocument(did: string): Promise<any | null> {
    if (!this.node) {
      throw new Error('P2P node is not started');
    }
    return resolveDidDocument(this.node, did);
  }

  /**
   * Gateway hook: Publishes a user's DID Document directly to the Kademlia DHT.
   */
  async registerDidDocument(did: string, publicKeyHex: string): Promise<void> {
    if (!this.node) {
      throw new Error('P2P node is not started');
    }
    await publishDidDocument(this.node, did, publicKeyHex);
  }

  /**
   * Gateway hook: Cryptographically validates a challenge-response signature using a user's DID.
   * Resolves the DID document from the Kademlia DHT to find the verification key.
   * If DHT lookup fails, it falls back to extracting the public key directly from the did:daup:<publicKeyHex> schema.
   */
  async verifyDidChallenge(
    did: string,
    challenge: string,
    signature: string
  ): Promise<boolean> {
    try {
      let publicKeyHex: string | null = null;
      const doc = await this.lookupDidDocument(did);

      if (doc && doc.verificationMethod && doc.verificationMethod.length > 0) {
        publicKeyHex = doc.verificationMethod[0].publicKeyHex;
      } else {
        // Fall back to direct offline parsing
        publicKeyHex = getPublicKeyFromDid(did);
      }

      if (!publicKeyHex) {
        return false;
      }

      return verifyData(challenge, signature, publicKeyHex);
    } catch (err) {
      return false;
    }
  }
}
