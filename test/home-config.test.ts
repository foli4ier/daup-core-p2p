import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { generateKeyPairHex, getDidFromPublicKey, ed25519SeedFromPkcs8Hex } from '../src/crypto.js';
import {
  DEFAULT_TCP_PORT,
  DEFAULT_WS_PORT,
  formatHomeNodeStartBanner,
  loadOrCreatePeerKey,
  parseListenAddrs,
  resolveHomeListenConfig,
  toBootstrapMultiaddrs
} from '../src/home-config.js';

describe('home listen config parsing', () => {
  it('defaults to TCP 4001 and WS 4002', () => {
    const addrs = parseListenAddrs({});
    expect(addrs).toEqual([
      `/ip4/0.0.0.0/tcp/${DEFAULT_TCP_PORT}`,
      `/ip4/0.0.0.0/tcp/${DEFAULT_WS_PORT}/ws`
    ]);
  });

  it('uses PORT and WS_PORT when set', () => {
    const config = resolveHomeListenConfig({
      PORT: '4101',
      WS_PORT: '4102'
    });
    expect(config.tcpPort).toBe(4101);
    expect(config.wsPort).toBe(4102);
    expect(config.listenAddrs).toEqual([
      '/ip4/0.0.0.0/tcp/4101',
      '/ip4/0.0.0.0/tcp/4102/ws'
    ]);
  });

  it('lets LISTEN_ADDRS override PORT / WS_PORT', () => {
    const addrs = parseListenAddrs({
      PORT: '4101',
      WS_PORT: '4102',
      LISTEN_ADDRS: '/ip4/127.0.0.1/tcp/5001,/ip4/127.0.0.1/tcp/5002/ws'
    });
    expect(addrs).toEqual([
      '/ip4/127.0.0.1/tcp/5001',
      '/ip4/127.0.0.1/tcp/5002/ws'
    ]);
  });

  it('omits the websocket listen addr when ENABLE_WS is false', () => {
    const config = resolveHomeListenConfig({ ENABLE_WS: 'false' });
    expect(config.enableWebSockets).toBe(false);
    expect(config.wsPort).toBeNull();
    expect(config.listenAddrs).toEqual(['/ip4/0.0.0.0/tcp/4001']);
  });

  it('rejects the same PORT and WS_PORT', () => {
    expect(() => resolveHomeListenConfig({ PORT: '4001', WS_PORT: '4001' })).toThrow(
      /WS_PORT must differ from PORT/
    );
  });

  it('rewrites unspecified hosts into bootstrap multiaddrs', () => {
    const peers = toBootstrapMultiaddrs(
      ['/ip4/0.0.0.0/tcp/4001', '/ip4/0.0.0.0/tcp/4002/ws'],
      '12D3KooWBootstrapPeer',
      ['192.168.1.10']
    );
    expect(peers).toEqual([
      '/ip4/192.168.1.10/tcp/4001/p2p/12D3KooWBootstrapPeer',
      '/ip4/192.168.1.10/tcp/4002/ws/p2p/12D3KooWBootstrapPeer'
    ]);
  });

  it('does not include a private key in the start banner', () => {
    const keys = generateKeyPairHex();
    const banner = formatHomeNodeStartBanner({
      did: 'did:daup:abc',
      peerId: '12D3KooWExample',
      listenAddrs: ['/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWExample'],
      bootstrapPeers: ['/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWExample']
    });
    expect(banner).toContain('DID: did:daup:abc');
    expect(banner).toContain('PeerId: 12D3KooWExample');
    expect(banner).toContain('BOOTSTRAP_PEERS');
    expect(banner).not.toContain(keys.privateKey);
    expect(banner.toLowerCase()).not.toContain('privatekey');
  });
});

describe('peer key file create-then-reuse', () => {
  it('generates a key file once and reuses it on the next load', () => {
    const dir = mkdtempSync(join(tmpdir(), 'daup-peer-key-'));
    const keyFilePath = join(dir, 'peer.key');

    try {
      const first = loadOrCreatePeerKey({ keyFilePath });
      expect(first.created).toBe(true);
      expect(first.source).toBe('generated');
      expect(first.privateKeyHex.length).toBeGreaterThan(64);

      const onDisk = readFileSync(keyFilePath, 'utf8').trim();
      expect(onDisk).toBe(first.privateKeyHex);

      const mode = statSync(keyFilePath).mode & 0o777;
      expect(mode).toBe(0o600);

      const second = loadOrCreatePeerKey({ keyFilePath });
      expect(second.created).toBe(false);
      expect(second.source).toBe('file');
      expect(second.privateKeyHex).toBe(first.privateKeyHex);

      expect(didFromPrivateKeyHex(second.privateKeyHex)).toBe(didFromPrivateKeyHex(first.privateKeyHex));
      expect(ed25519SeedFromPkcs8Hex(second.privateKeyHex)).toEqual(
        ed25519SeedFromPkcs8Hex(first.privateKeyHex)
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('prefers PRIVATE_KEY over an existing key file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'daup-peer-key-env-'));
    const keyFilePath = join(dir, 'peer.key');
    const fileKey = generateKeyPairHex();
    const envKey = generateKeyPairHex();
    writeFileSync(keyFilePath, `${fileKey.privateKey}\n`, { mode: 0o600 });

    try {
      const loaded = loadOrCreatePeerKey({
        privateKeyHex: envKey.privateKey,
        keyFilePath
      });
      expect(loaded.source).toBe('env');
      expect(loaded.privateKeyHex).toBe(envKey.privateKey);
      expect(loaded.privateKeyHex).not.toBe(fileKey.privateKey);
      expect(readFileSync(keyFilePath, 'utf8').trim()).toBe(fileKey.privateKey);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an empty key file instead of silently regenerating', () => {
    const dir = mkdtempSync(join(tmpdir(), 'daup-peer-key-empty-'));
    const keyFilePath = join(dir, 'peer.key');
    writeFileSync(keyFilePath, '   \n');

    try {
      expect(() => loadOrCreatePeerKey({ keyFilePath })).toThrow(/empty/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function didFromPrivateKeyHex(privateKeyHex: string): string {
  const privKeyObj = createPrivateKey({
    key: Buffer.from(privateKeyHex, 'hex'),
    format: 'der',
    type: 'pkcs8'
  });
  const publicKeyHex = createPublicKey(privKeyObj).export({ type: 'spki', format: 'der' }).toString('hex');
  return getDidFromPublicKey(publicKeyHex);
}

describe('ed25519 seed extraction', () => {
  it('returns a stable 32-byte seed from a PKCS8 hex key', () => {
    const keys = generateKeyPairHex();
    const seed = ed25519SeedFromPkcs8Hex(keys.privateKey);
    expect(seed.length).toBe(32);
    expect(ed25519SeedFromPkcs8Hex(keys.privateKey)).toEqual(seed);
    expect(getDidFromPublicKey(keys.publicKey)).toMatch(/^did:daup:/);
  });
});
