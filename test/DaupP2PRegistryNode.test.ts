import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { 
  DaupP2PRegistryNode, 
  AppManifest, 
  signAppManifest, 
  verifyAppManifestSignature 
} from '../src/DaupP2PRegistryNode.js';
import { generateKeyPairHex, getDidFromPublicKey, signData } from '../src/crypto.js';

describe('DaupP2PRegistryNode Integration Tests', () => {
  let nodeA: DaupP2PRegistryNode;
  let nodeB: DaupP2PRegistryNode;

  beforeAll(async () => {
    // 1. Initialize Node A (Bootstrap node)
    nodeA = new DaupP2PRegistryNode();
    await nodeA.start({
      listenAddrs: ['/ip4/127.0.0.1/tcp/0', '/ip4/127.0.0.1/tcp/0/ws'],
      enableWebRTC: false,
      enableWebSockets: true
    });

    const addrs = nodeA.node.getMultiaddrs().map((a: any) => a.toString());
    // Find the standard TCP multiaddr of Node A
    const bootstrapAddr = addrs.find((a: string) => a.includes('127.0.0.1') && !a.includes('/ws'));
    if (!bootstrapAddr) {
      throw new Error('Node A failed to allocate a loopback TCP listen address');
    }

    // 2. Initialize Node B and point to Node A as the bootstrap peer
    nodeB = new DaupP2PRegistryNode();
    await nodeB.start({
      listenAddrs: ['/ip4/127.0.0.1/tcp/0', '/ip4/127.0.0.1/tcp/0/ws'],
      bootstrapAddrs: [bootstrapAddr],
      enableWebRTC: false,
      enableWebSockets: true
    });

    // Wait up to 5 seconds for connection and handshakes to finish
    const start = Date.now();
    let connected = false;
    while (Date.now() - start < 5000) {
      if (
        nodeA.registry.getVerifiedPeers().length > 0 &&
        nodeB.registry.getVerifiedPeers().length > 0
      ) {
        connected = true;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (!connected) {
      throw new Error('Failed to establish peer connection and handshake between registry nodes');
    }

    // Crucial: Wait for the identify protocol to finish exchanging supported protocols
    // (such as '/daup/kad/1.0.0') and populate the peerStore before executing DHT queries.
    await new Promise(resolve => setTimeout(resolve, 2500));
  });

  afterAll(async () => {
    await nodeB.stop();
    await nodeA.stop();
  });

  it('should successfully serialize, publish, and fetch an AppManifest on the DHT', async () => {
    const publisherKeys = generateKeyPairHex();
    const publisherDid = getDidFromPublicKey(publisherKeys.publicKey);

    const unsignedManifest: Omit<AppManifest, 'signature'> = {
      appId: 'daup-farmer-test',
      version: '1.2.0',
      name: 'Daup Farmer Test App',
      description: 'A mock farmer telemetry decentralized application',
      icon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      wasmBinaryHash: 'bafybeicg2vxspcxbf74dq23jrxkm5u4mfsz35vfqsnwxts72n54g64kmua',
      wasmBinaryUrl: 'https://registry.daup.io/binaries/farmer-v1.2.0.wasm',
      versionHash: 'mock-version-hash-8899aabbcc',
      publisherDid,
      timestamp: Date.now()
    };

    // Sign the manifest
    const signedManifest = signAppManifest(unsignedManifest, publisherKeys.privateKey);

    // Verify signature helper works
    expect(verifyAppManifestSignature(signedManifest)).toBe(true);

    console.log('[TEST] Publishing App Manifest...');
    // Publish from Node B
    await nodeB.publishAppManifest(signedManifest);
    console.log('[TEST] App Manifest Published successfully!');

    // Settle DHT
    await new Promise(resolve => setTimeout(resolve, 500));

    console.log('[TEST] Fetching App Manifest by App ID...');
    // Fetch by App ID from Node A
    const fetchedByAppId = await nodeA.fetchAppManifest(signedManifest.appId);
    console.log('[TEST] Fetched App Manifest by App ID:', fetchedByAppId ? 'FOUND' : 'NOT FOUND');
    expect(fetchedByAppId).not.toBeNull();
    expect(fetchedByAppId!.appId).toBe(signedManifest.appId);
    expect(fetchedByAppId!.version).toBe(signedManifest.version);
    expect(fetchedByAppId!.wasmBinaryHash).toBe(signedManifest.wasmBinaryHash);
    expect(fetchedByAppId!.signature).toBe(signedManifest.signature);

    console.log('[TEST] Fetching App Manifest by Version Hash...');
    // Fetch by Version Hash from Node A
    const fetchedByHash = await nodeA.fetchAppManifest(signedManifest.versionHash);
    console.log('[TEST] Fetched App Manifest by Version Hash:', fetchedByHash ? 'FOUND' : 'NOT FOUND');
    expect(fetchedByHash).not.toBeNull();
    expect(fetchedByHash!.appId).toBe(signedManifest.appId);
    expect(fetchedByHash!.versionHash).toBe(signedManifest.versionHash);
  }, 15000); // 15s timeout

  it('should broadcast and receive real-time updates over Gossipsub topics', async () => {
    const manifest: AppManifest = {
      appId: 'daup-manufacturer-test',
      version: '2.0.1',
      name: 'Daup Manufacturer Test App',
      description: 'Deconstructive manufacturing floor tracker',
      wasmBinaryHash: 'wasm-hash-990011',
      versionHash: 'mock-version-hash-manufacturer-201',
      publisherDid: nodeB.did,
      timestamp: Date.now()
    };

    const renewalEvent = {
      did: 'did:daup:user-subscriber-123',
      tier: 'premium',
      expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000
    };

    let receivedManifest: AppManifest | null = null;
    let receivedRenewal: any | null = null;

    // Node A subscribes to releases and renewals
    nodeA.subscribeToReleases((manifest, env) => {
      receivedManifest = manifest;
    });

    nodeA.subscribeToRenewals((renewal, env) => {
      receivedRenewal = renewal;
    });

    // Settle pubsub subscription routing propagation
    await new Promise(resolve => setTimeout(resolve, 500));

    // Node B broadcasts the updates
    await nodeB.broadcastAppRelease(manifest);
    await nodeB.broadcastSubscriptionRenewal(renewalEvent);

    // Wait up to 3 seconds for broadcast receipts
    const start = Date.now();
    while (Date.now() - start < 3000) {
      if (receivedManifest && receivedRenewal) {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    expect(receivedManifest).not.toBeNull();
    expect(receivedManifest!.appId).toBe(manifest.appId);
    expect(receivedManifest!.version).toBe(manifest.version);

    expect(receivedRenewal).not.toBeNull();
    expect(receivedRenewal!.did).toBe(renewalEvent.did);
    expect(receivedRenewal!.tier).toBe(renewalEvent.tier);
  });

  it('should support microservice challenge-response validation using user DIDs', async () => {
    // Generate simulated user identity
    const userKeys = generateKeyPairHex();
    const userDid = getDidFromPublicKey(userKeys.publicKey);

    // Create a challenge payload and sign it
    const challenge = 'prove-ownership-challenge-4567';
    const signature = signData(challenge, userKeys.privateKey);

    // 1. Direct offline DID validation (where DID document isn't registered in DHT yet)
    console.log('[TEST] Verifying offline DID challenge...');
    const offlineIsValid = await nodeA.verifyDidChallenge(userDid, challenge, signature);
    console.log('[TEST] Offline DID challenge verified:', offlineIsValid);
    expect(offlineIsValid).toBe(true);

    // Tampered signature or challenge must fail
    const offlineIsInvalid = await nodeA.verifyDidChallenge(userDid, challenge, 'invalid-signature-hex');
    expect(offlineIsInvalid).toBe(false);

    // 2. DHT document registration and online validation lookup
    console.log('[TEST] Registering DID Document...');
    await nodeB.registerDidDocument(userDid, userKeys.publicKey);
    console.log('[TEST] DID Document registered!');

    // Wait a brief moment for Kademlia DHT put/get routing table update
    await new Promise(resolve => setTimeout(resolve, 500));

    console.log('[TEST] Looking up DID Document...');
    // Look up the DID document on Node A from DHT
    const doc = await nodeA.lookupDidDocument(userDid);
    console.log('[TEST] DID Document lookup returned:', doc ? 'FOUND' : 'NOT FOUND');
    expect(doc).not.toBeNull();
    expect(doc!.id).toBe(userDid);
    expect(doc!.verificationMethod[0].publicKeyHex).toBe(userKeys.publicKey);

    console.log('[TEST] Verifying online DID challenge...');
    // Online verification must succeed (using DHT resolved public key verification method)
    const onlineIsValid = await nodeA.verifyDidChallenge(userDid, challenge, signature);
    console.log('[TEST] Online DID challenge verified:', onlineIsValid);
    expect(onlineIsValid).toBe(true);
  }, 15000); // 15s timeout
});
