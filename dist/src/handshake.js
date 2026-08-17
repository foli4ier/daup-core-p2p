import * as lp from 'it-length-prefixed';
import { randomBytes } from 'node:crypto';
import { verifyData, signData, getPublicKeyFromDid } from './crypto.js';
/**
 * Registry to hold active and verified peer mappings.
 */
export class ActiveStateRegistry {
    peerIdToDid = new Map();
    didToPublicKey = new Map();
    peerIdToPublicKey = new Map();
    addVerifiedPeer(peerId, did, publicKey) {
        this.peerIdToDid.set(peerId, did);
        this.didToPublicKey.set(did, publicKey);
        this.peerIdToPublicKey.set(peerId, publicKey);
    }
    removePeer(peerId) {
        const did = this.peerIdToDid.get(peerId);
        this.peerIdToDid.delete(peerId);
        this.peerIdToPublicKey.delete(peerId);
        if (did) {
            this.didToPublicKey.delete(did);
        }
    }
    isPeerVerified(peerId) {
        return this.peerIdToDid.has(peerId);
    }
    getDid(peerId) {
        return this.peerIdToDid.get(peerId);
    }
    getPublicKey(peerId) {
        return this.peerIdToPublicKey.get(peerId);
    }
    getVerifiedPeers() {
        return Array.from(this.peerIdToDid.keys());
    }
}
/**
 * Helper to read and write length-prefixed JSON messages over a libp2p stream.
 * Bypasses it-pipe to work directly with YamuxStream's send and async iterator methods.
 */
export class HandshakeSession {
    stream;
    sourceIterator;
    closed = false;
    constructor(stream) {
        this.stream = stream;
        const decoded = lp.decode(stream);
        this.sourceIterator = decoded[Symbol.asyncIterator]();
    }
    async readMessage() {
        const { value, done } = await this.sourceIterator.next();
        if (done || !value) {
            throw new Error('Connection closed prematurely');
        }
        const bytes = value.subarray ? value.subarray() : new Uint8Array(value);
        const text = new TextDecoder().decode(bytes);
        return JSON.parse(text);
    }
    async writeMessage(msg) {
        if (this.closed)
            throw new Error('Handshake session is closed');
        const text = JSON.stringify(msg);
        const bytes = new TextEncoder().encode(text);
        const framed = lp.encode.single(bytes);
        await this.stream.send(framed);
    }
    async close() {
        if (this.closed)
            return;
        this.closed = true;
        try {
            await this.stream.close();
        }
        catch (err) {
            // Ignore close errors
        }
    }
}
/**
 * Runs the symmetric handshake sequence from the initiator's side (Node A).
 */
export async function runInitiatorHandshake(stream, remotePeerId, localDid, localPublicKey, localPrivateKey, localPeerId, registry) {
    const session = new HandshakeSession(stream);
    try {
        // 1. Send our Identity
        await session.writeMessage({
            type: 'identity',
            did: localDid,
            publicKey: localPublicKey,
            peerId: localPeerId
        });
        // 2. Receive remote Identity
        const msg1 = await session.readMessage();
        if (msg1.type !== 'identity') {
            throw new Error(`Expected identity message, got ${msg1.type}`);
        }
        if (msg1.peerId !== remotePeerId) {
            throw new Error(`Peer ID mismatch: connection says ${remotePeerId}, handshake says ${msg1.peerId}`);
        }
        // Check that the DID suffix matches the public key
        const derivedPubKey = getPublicKeyFromDid(msg1.did);
        if (derivedPubKey !== msg1.publicKey) {
            throw new Error(`DID structure invalid: suffix does not match public key`);
        }
        // 3. Receive remote Challenge
        const msg2 = await session.readMessage();
        if (msg2.type !== 'challenge') {
            throw new Error(`Expected challenge message, got ${msg2.type}`);
        }
        // 4. Sign remote challenge & Send Response
        const signature = signData(msg2.nonce, localPrivateKey);
        await session.writeMessage({
            type: 'response',
            signature
        });
        // 5. Generate our Challenge & Send
        const localNonce = randomBytes(32).toString('hex');
        await session.writeMessage({
            type: 'challenge',
            nonce: localNonce
        });
        // 6. Receive remote Response & Verify
        const msg3 = await session.readMessage();
        if (msg3.type !== 'response') {
            throw new Error(`Expected response message, got ${msg3.type}`);
        }
        const isValid = verifyData(localNonce, msg3.signature, msg1.publicKey);
        if (!isValid) {
            throw new Error('Symmetric handshake failed: Remote challenge response signature verification failed');
        }
        // Handshake successful! Add to registry.
        registry.addVerifiedPeer(remotePeerId, msg1.did, msg1.publicKey);
    }
    finally {
        await session.close();
    }
}
/**
 * Runs the symmetric handshake sequence from the responder's side (Node B).
 */
export async function runResponderHandshake(stream, remotePeerId, localDid, localPublicKey, localPrivateKey, localPeerId, registry) {
    const session = new HandshakeSession(stream);
    try {
        // 1. Receive remote Identity
        const msg1 = await session.readMessage();
        if (msg1.type !== 'identity') {
            throw new Error(`Expected identity message, got ${msg1.type}`);
        }
        if (msg1.peerId !== remotePeerId) {
            throw new Error(`Peer ID mismatch: connection says ${remotePeerId}, handshake says ${msg1.peerId}`);
        }
        // Check that the DID suffix matches the public key
        const derivedPubKey = getPublicKeyFromDid(msg1.did);
        if (derivedPubKey !== msg1.publicKey) {
            throw new Error(`DID structure invalid: suffix does not match public key`);
        }
        // 2. Send our Identity
        await session.writeMessage({
            type: 'identity',
            did: localDid,
            publicKey: localPublicKey,
            peerId: localPeerId
        });
        // 3. Generate our Challenge & Send
        const localNonce = randomBytes(32).toString('hex');
        await session.writeMessage({
            type: 'challenge',
            nonce: localNonce
        });
        // 4. Receive remote Response & Verify
        const msg2 = await session.readMessage();
        if (msg2.type !== 'response') {
            throw new Error(`Expected response message, got ${msg2.type}`);
        }
        const isValid = verifyData(localNonce, msg2.signature, msg1.publicKey);
        if (!isValid) {
            throw new Error('Symmetric handshake failed: Remote challenge response signature verification failed');
        }
        // 5. Receive remote Challenge
        const msg3 = await session.readMessage();
        if (msg3.type !== 'challenge') {
            throw new Error(`Expected challenge message, got ${msg3.type}`);
        }
        // 6. Sign remote challenge & Send Response
        const signature = signData(msg3.nonce, localPrivateKey);
        await session.writeMessage({
            type: 'response',
            signature
        });
        // Handshake successful! Add to registry.
        registry.addVerifiedPeer(remotePeerId, msg1.did, msg1.publicKey);
    }
    finally {
        await session.close();
    }
}
