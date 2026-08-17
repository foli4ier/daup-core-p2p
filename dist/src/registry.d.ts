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
export declare function publishDidDocument(node: any, did: string, publicKeyHex: string): Promise<void>;
/**
 * Resolves a DID Document from the Kademlia DHT.
 */
export declare function resolveDidDocument(node: any, did: string): Promise<DidDocument | null>;
