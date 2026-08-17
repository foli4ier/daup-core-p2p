import { ActiveStateRegistry } from './handshake.js';
import { MessageEnvelope } from './envelope.js';
export interface P2PNodeOptions {
    privateKeyHex?: string;
    listenAddrs?: string[];
    bootstrapAddrs?: string[];
    enableWebRTC?: boolean;
    enableWebSockets?: boolean;
}
export declare class P2PNode {
    node: any;
    registry: ActiveStateRegistry;
    did: string;
    publicKeyHex: string;
    privateKeyHex: string;
    constructor(options?: P2PNodeOptions);
    /**
     * Configures, initializes, and starts the libp2p node.
     */
    start(options?: P2PNodeOptions): Promise<void>;
    /**
     * Stops the libp2p node.
     */
    stop(): Promise<void>;
    /**
     * Publishes a message over GossipSub wrapped in a MessageEnvelope.
     */
    publishMessage(topic: string, payload: string): Promise<void>;
    /**
     * Subscribes to a GossipSub topic and registers a message callback.
     * Automatically validates the MessageEnvelope signature, timestamp drift, and format.
     */
    subscribeToTopic(topic: string, onMessage: (payload: string, envelope: MessageEnvelope) => void): void;
    /**
     * Manually registers a peer to Kademlia DHT by loading its addresses and protocols
     * from the peerStore and invoking the DHT's onPeerConnect handler.
     */
    registerPeerToDht(peerIdObj: any): Promise<void>;
}
