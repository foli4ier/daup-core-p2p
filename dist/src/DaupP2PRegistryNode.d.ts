import { P2PNode } from './node.js';
import { MessageEnvelope } from './envelope.js';
/**
 * Interface representing a decentralized application manifest.
 */
export interface AppManifest {
    appId: string;
    version: string;
    name: string;
    description: string;
    icon?: string;
    wasmBinaryHash: string;
    wasmBinaryUrl?: string;
    versionHash: string;
    publisherDid: string;
    timestamp: number;
    signature?: string;
}
/**
 * Construct a deterministic payload string for signing or verifying an AppManifest.
 */
export declare function getAppManifestSigningPayload(manifest: Omit<AppManifest, 'signature'>): string;
/**
 * Helper to cryptographically sign an AppManifest using an Ed25519 private key.
 */
export declare function signAppManifest(manifest: Omit<AppManifest, 'signature'>, privateKeyHex: string): AppManifest;
/**
 * Helper to cryptographically verify an AppManifest's publisher signature.
 */
export declare function verifyAppManifestSignature(manifest: AppManifest): boolean;
/**
 * Specialized P2P registry node for the DAUP ecosystem.
 * Extends the baseline P2PNode to enable Kademlia DHT queries and pubsub broadcasts.
 */
export declare class DaupP2PRegistryNode extends P2PNode {
    /**
     * Publishes an application manifest to the Kademlia DHT.
     * Writes the manifest under both the App ID and the specific Version Hash.
     */
    publishAppManifest(manifest: AppManifest): Promise<void>;
    /**
     * Retrieves and parses an AppManifest from Kademlia DHT.
     * @param cidOrKey The key to query, which can be an App ID, Version Hash, or fully qualified path.
     */
    fetchAppManifest(cidOrKey: string): Promise<AppManifest | null>;
    /**
     * Broadcasts a new application release event to all connected peers via Gossipsub.
     */
    broadcastAppRelease(manifest: AppManifest): Promise<void>;
    /**
     * Broadcasts a subscription renewal event to all connected peers via Gossipsub.
     */
    broadcastSubscriptionRenewal(renewal: any): Promise<void>;
    /**
     * Registers a listener to intercept real-time application release broadcasts.
     */
    subscribeToReleases(onRelease: (manifest: AppManifest, envelope: MessageEnvelope) => void): void;
    /**
     * Registers a listener to intercept real-time subscription renewal broadcasts.
     */
    subscribeToRenewals(onRenewal: (renewal: any, envelope: MessageEnvelope) => void): void;
    /**
     * Gateway hook: Looks up a user's DID Document from the Kademlia DHT.
     */
    lookupDidDocument(did: string): Promise<any | null>;
    /**
     * Gateway hook: Publishes a user's DID Document directly to the Kademlia DHT.
     */
    registerDidDocument(did: string, publicKeyHex: string): Promise<void>;
    /**
     * Gateway hook: Cryptographically validates a challenge-response signature using a user's DID.
     * Resolves the DID document from the Kademlia DHT to find the verification key.
     * If DHT lookup fails, it falls back to extracting the public key directly from the did:daup:<publicKeyHex> schema.
     */
    verifyDidChallenge(did: string, challenge: string, signature: string): Promise<boolean>;
}
