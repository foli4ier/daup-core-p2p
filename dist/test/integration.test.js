import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { P2PNode } from '../src/node.js';
describe('P2P Network Integration', () => {
    let nodeA;
    let nodeB;
    beforeAll(async () => {
        // 1. Start Node A (acting as the bootstrap / listener node)
        nodeA = new P2PNode();
        await nodeA.start({
            listenAddrs: ['/ip4/127.0.0.1/tcp/0'],
            enableWebRTC: false // Disable WebRTC during local unit tests for speed/reliability
        });
        // Get the actual allocated listen address of Node A
        const addrs = nodeA.node.getMultiaddrs().map((a) => a.toString());
        const bootstrapAddr = addrs.find((a) => a.includes('127.0.0.1'));
        if (!bootstrapAddr) {
            throw new Error('Node A failed to allocate a loopback listen address');
        }
        // 2. Start Node B and configure Node A as its bootstrap node
        nodeB = new P2PNode();
        await nodeB.start({
            listenAddrs: ['/ip4/127.0.0.1/tcp/0'],
            bootstrapAddrs: [bootstrapAddr],
            enableWebRTC: false
        });
    });
    afterAll(async () => {
        // Cleanup nodes
        await nodeB.stop();
        await nodeA.stop();
    });
    it('should establish connection, run automated peer discovery, and complete symmetric handshakes', async () => {
        // Wait for the connection and handshake to conclude (max 5 seconds)
        const start = Date.now();
        let verified = false;
        while (Date.now() - start < 5000) {
            const peersA = nodeA.registry.getVerifiedPeers();
            const peersB = nodeB.registry.getVerifiedPeers();
            if (peersA.length > 0 && peersB.length > 0) {
                verified = true;
                break;
            }
            await new Promise(resolve => setTimeout(resolve, 200));
        }
        expect(verified).toBe(true);
        const verifiedA = nodeA.registry.getVerifiedPeers();
        const verifiedB = nodeB.registry.getVerifiedPeers();
        expect(verifiedA).toContain(nodeB.node.peerId.toString());
        expect(verifiedB).toContain(nodeA.node.peerId.toString());
        // Verify registration maps DID and public keys correctly
        expect(nodeA.registry.getDid(nodeB.node.peerId.toString())).toBe(nodeB.did);
        expect(nodeA.registry.getPublicKey(nodeB.node.peerId.toString())).toBe(nodeB.publicKeyHex);
    });
    it('should successfully subscribe, publish, and verify GossipSub message envelopes', async () => {
        const topic = 'test-broadcast';
        const messagePayload = 'hello from node B!';
        let receivedPayload = null;
        let receivedEnvelope = null;
        // Node A subscribes
        nodeA.subscribeToTopic(topic, (payload, envelope) => {
            receivedPayload = payload;
            receivedEnvelope = envelope;
        });
        // Allow subscription routing tables to propagate
        await new Promise(resolve => setTimeout(resolve, 500));
        // Node B publishes
        await nodeB.publishMessage(topic, messagePayload);
        // Wait for receipt (max 3 seconds)
        const start = Date.now();
        while (Date.now() - start < 3000) {
            if (receivedPayload !== null) {
                break;
            }
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        expect(receivedPayload).toBe(messagePayload);
        expect(receivedEnvelope).not.toBeNull();
        expect(receivedEnvelope.senderDid).toBe(nodeB.did);
        expect(receivedEnvelope.version).toBe('1.0.0');
        expect(receivedEnvelope.signature).toBeTypeOf('string');
    });
});
