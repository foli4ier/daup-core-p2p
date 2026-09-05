import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { webSockets } from '@libp2p/websockets';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { kadDHT } from '@libp2p/kad-dht';
import { gossipsub } from '@libp2p/gossipsub';
import { identify, identifyPush } from '@libp2p/identify';
import { ping } from '@libp2p/ping';
import { generateKeyPairFromSeed } from '@libp2p/crypto/keys';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { multiaddr } from '@multiformats/multiaddr';
import { ed25519SeedFromPkcs8Hex, generateKeyPairHex, getDidFromPublicKey } from './crypto.js';
import { ActiveStateRegistry, runInitiatorHandshake, runResponderHandshake } from './handshake.js';
import { createEnvelope, verifyEnvelope } from './envelope.js';
export class P2PNode {
    node;
    registry = new ActiveStateRegistry();
    did;
    publicKeyHex;
    privateKeyHex;
    constructor(options = {}) {
        if (options.privateKeyHex) {
            this.privateKeyHex = options.privateKeyHex;
            // Reconstruct public key from private key
            const privKeyObj = createPrivateKey({
                key: Buffer.from(this.privateKeyHex, 'hex'),
                format: 'der',
                type: 'pkcs8'
            });
            const pubKeyObj = createPublicKey(privKeyObj);
            this.publicKeyHex = pubKeyObj.export({ type: 'spki', format: 'der' }).toString('hex');
        }
        else {
            const keys = generateKeyPairHex();
            this.privateKeyHex = keys.privateKey;
            this.publicKeyHex = keys.publicKey;
        }
        this.did = getDidFromPublicKey(this.publicKeyHex);
    }
    /**
     * Configures, initializes, and starts the libp2p node.
     */
    async start(options = {}) {
        const enableWebSockets = options.enableWebSockets !== false; // Default true
        let listenAddrs = options.listenAddrs;
        if (!listenAddrs) {
            listenAddrs = ['/ip4/0.0.0.0/tcp/0'];
            if (enableWebSockets) {
                listenAddrs.push('/ip4/0.0.0.0/tcp/0/ws');
            }
        }
        const bootstrapAddrs = options.bootstrapAddrs || [];
        const enableWebRTC = options.enableWebRTC !== false; // Default true
        const transports = [tcp()];
        if (enableWebRTC) {
            try {
                const { webRTC } = await import('@libp2p/webrtc');
                transports.push(webRTC());
            }
            catch (err) {
                console.warn(`[Node] Could not enable WebRTC transport (native package might be missing): ${err.message}`);
            }
        }
        if (enableWebSockets) {
            try {
                transports.push(webSockets());
            }
            catch (err) {
                console.warn(`[Node] Could not enable WebSockets transport: ${err.message}`);
            }
        }
        // 1. Create the libp2p instance (PeerId derived from the persisted DAUP key)
        const privateKey = await generateKeyPairFromSeed('Ed25519', ed25519SeedFromPkcs8Hex(this.privateKeyHex));
        this.node = await createLibp2p({
            privateKey,
            addresses: {
                listen: listenAddrs
            },
            transports,
            connectionEncrypters: [noise()],
            streamMuxers: [yamux()],
            services: {
                identify: identify(),
                identifyPush: identifyPush(),
                ping: ping(),
                dht: kadDHT({
                    clientMode: false, // Run as DHT server node
                    protocol: '/daup/kad/1.0.0',
                    validators: {
                        dids: async () => { },
                        apps: async () => { }
                    },
                    selectors: {
                        dids: () => 0,
                        apps: () => 0
                    },
                    peerInfoMapper: (peer) => peer
                }),
                pubsub: gossipsub({
                    emitSelf: true,
                    allowPublishToZeroTopicPeers: true
                })
            }
        });
        // 2. Setup handshake protocol handling
        this.node.handle('/daup/handshake/1.0.0', async (incoming, connection) => {
            let stream = incoming;
            let conn = connection;
            if (incoming && incoming.stream) {
                stream = incoming.stream;
                conn = incoming.connection;
            }
            const remotePeerId = conn.remotePeer.toString();
            try {
                await runResponderHandshake(stream, remotePeerId, this.did, this.publicKeyHex, this.privateKeyHex, this.node.peerId.toString(), this.registry);
                console.log(`[Handshake] Symmetrically verified peer (Responder side): ${remotePeerId}`);
                void this.registerPeerToDht(conn.remotePeer);
            }
            catch (err) {
                console.error(`[Handshake] Failed responder handshake with ${remotePeerId}:`, err.message);
                await stream.close();
                await conn.close();
            }
        });
        // 3. Automated handshake triggers (on outbound connection establishment)
        this.node.addEventListener('connection:open', async (evt) => {
            const connection = evt.detail;
            if (connection.direction === 'outbound') {
                const remotePeerId = connection.remotePeer.toString();
                // Wait a small bit to let Yamux initialize properly over the stream before dialing protocol
                setTimeout(async () => {
                    try {
                        const stream = await this.node.dialProtocol(connection.remotePeer, '/daup/handshake/1.0.0');
                        await runInitiatorHandshake(stream, remotePeerId, this.did, this.publicKeyHex, this.privateKeyHex, this.node.peerId.toString(), this.registry);
                        console.log(`[Handshake] Symmetrically verified peer (Initiator side): ${remotePeerId}`);
                        void this.registerPeerToDht(connection.remotePeer);
                    }
                    catch (err) {
                        console.error(`[Handshake] Failed initiator handshake with ${remotePeerId}:`, err.message);
                        await connection.close();
                    }
                }, 100);
            }
        });
        // 4. Automated peer discovery and connection listeners
        this.node.addEventListener('peer:discovery', async (evt) => {
            const peerInfo = evt.detail;
            const peerIdStr = peerInfo.id.toString();
            // Only dial if not already connected
            const currentConnections = this.node.getConnections(peerInfo.id);
            if (currentConnections.length === 0) {
                console.log(`[Discovery] Discovered new peer ${peerIdStr}, dialing...`);
                try {
                    await this.node.dial(peerInfo.id);
                }
                catch (err) {
                    // Ignore dial errors during discovery
                }
            }
        });
        this.node.addEventListener('peer:connect', (evt) => {
            console.log(`[Connection] Connected to peer: ${evt.detail.toString()}`);
        });
        this.node.addEventListener('peer:disconnect', (evt) => {
            const peerIdStr = evt.detail.toString();
            console.log(`[Connection] Disconnected from peer: ${peerIdStr}`);
            this.registry.removePeer(peerIdStr);
        });
        // 5. Start the node
        await this.node.start();
        console.log(`[Node] Libp2p node started. Peer ID: ${this.node.peerId.toString()}`);
        console.log(`[Node] App Identity: ${this.did}`);
        // 6. Connect to bootstrap nodes if specified
        if (bootstrapAddrs.length > 0) {
            console.log(`[Bootstrap] Connecting to ${bootstrapAddrs.length} bootstrap peers...`);
            for (const addr of bootstrapAddrs) {
                try {
                    const ma = multiaddr(addr);
                    await this.node.dial(ma);
                    console.log(`[Bootstrap] Connected to bootstrap node: ${addr}`);
                }
                catch (err) {
                    console.error(`[Bootstrap] Failed to dial bootstrap node ${addr}:`, err.message);
                }
            }
        }
    }
    /**
     * Stops the libp2p node.
     */
    async stop() {
        if (this.node) {
            await this.node.stop();
            console.log('[Node] Libp2p node stopped.');
        }
    }
    /**
     * Publishes a message over GossipSub wrapped in a MessageEnvelope.
     */
    async publishMessage(topic, payload) {
        if (!this.node) {
            throw new Error('Node is not started');
        }
        const envelope = createEnvelope(payload, this.did, this.privateKeyHex);
        const serialized = JSON.stringify(envelope);
        const data = new TextEncoder().encode(serialized);
        await this.node.services.pubsub.publish(topic, data);
    }
    /**
     * Subscribes to a GossipSub topic and registers a message callback.
     * Automatically validates the MessageEnvelope signature, timestamp drift, and format.
     */
    subscribeToTopic(topic, onMessage) {
        if (!this.node) {
            throw new Error('Node is not started');
        }
        this.node.services.pubsub.subscribe(topic);
        this.node.services.pubsub.addEventListener('message', (evt) => {
            const msg = evt.detail;
            if (msg.topic === topic) {
                try {
                    const text = new TextDecoder().decode(msg.data);
                    const envelope = JSON.parse(text);
                    // Verify signature and validation constraints
                    const isValid = verifyEnvelope(envelope);
                    if (isValid) {
                        onMessage(envelope.payload, envelope);
                    }
                    else {
                        console.warn(`[GossipSub] Received invalid or signature-failed envelope on topic: ${topic}`);
                    }
                }
                catch (err) {
                    console.error('[GossipSub] Error parsing/verifying pubsub envelope:', err.message);
                }
            }
        });
    }
    /**
     * Manually registers a peer to Kademlia DHT by loading its addresses and protocols
     * from the peerStore and invoking the DHT's onPeerConnect handler.
     */
    async registerPeerToDht(peerIdObj) {
        try {
            const dht = this.node.services.dht;
            if (!dht)
                return;
            const dhtProtocol = dht.protocol || '/daup/kad/1.0.0';
            const startTime = Date.now();
            let registered = false;
            while (Date.now() - startTime < 8000) {
                let peer;
                try {
                    peer = await this.node.peerStore.get(peerIdObj);
                }
                catch (e) {
                    // ignore not found in store yet
                }
                if (peer && peer.protocols.includes(dhtProtocol)) {
                    const peerData = {
                        id: peerIdObj,
                        multiaddrs: peer.addresses.map((a) => a.multiaddr),
                        protocols: peer.protocols
                    };
                    await dht.onPeerConnect(peerData);
                    registered = true;
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 200));
            }
            if (!registered) {
                console.warn(`[DHT] Timed out waiting for peer ${peerIdObj.toString()} to advertise DHT protocol.`);
            }
        }
        catch (err) {
            console.warn(`[DHT] Failed manual registration for peer ${peerIdObj.toString()}:`, err.message);
        }
    }
}
