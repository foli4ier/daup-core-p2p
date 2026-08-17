export type HandshakeMsg = {
    type: 'identity';
    did: string;
    publicKey: string;
    peerId: string;
} | {
    type: 'challenge';
    nonce: string;
} | {
    type: 'response';
    signature: string;
};
/**
 * Registry to hold active and verified peer mappings.
 */
export declare class ActiveStateRegistry {
    private peerIdToDid;
    private didToPublicKey;
    private peerIdToPublicKey;
    addVerifiedPeer(peerId: string, did: string, publicKey: string): void;
    removePeer(peerId: string): void;
    isPeerVerified(peerId: string): boolean;
    getDid(peerId: string): string | undefined;
    getPublicKey(peerId: string): string | undefined;
    getVerifiedPeers(): string[];
}
/**
 * Helper to read and write length-prefixed JSON messages over a libp2p stream.
 * Bypasses it-pipe to work directly with YamuxStream's send and async iterator methods.
 */
export declare class HandshakeSession {
    private stream;
    private sourceIterator;
    private closed;
    constructor(stream: any);
    readMessage(): Promise<HandshakeMsg>;
    writeMessage(msg: HandshakeMsg): Promise<void>;
    close(): Promise<void>;
}
/**
 * Runs the symmetric handshake sequence from the initiator's side (Node A).
 */
export declare function runInitiatorHandshake(stream: any, remotePeerId: string, localDid: string, localPublicKey: string, localPrivateKey: string, localPeerId: string, registry: ActiveStateRegistry): Promise<void>;
/**
 * Runs the symmetric handshake sequence from the responder's side (Node B).
 */
export declare function runResponderHandshake(stream: any, remotePeerId: string, localDid: string, localPublicKey: string, localPrivateKey: string, localPeerId: string, registry: ActiveStateRegistry): Promise<void>;
