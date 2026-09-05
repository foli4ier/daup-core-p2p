import { mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync, existsSync, unlinkSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { networkInterfaces } from 'node:os';
import { generateKeyPairHex } from './crypto.js';
export const DEFAULT_TCP_PORT = 4001;
export const DEFAULT_WS_PORT = 4002;
export const DEFAULT_PEER_KEY_FILE = '.daup/peer.key';
/**
 * Parse PORT / WS_PORT / LISTEN_ADDRS for the always-on home / seed profile.
 * LISTEN_ADDRS (comma-separated) wins when set.
 */
export function parseListenAddrs(env = {}) {
    return resolveHomeListenConfig(env).listenAddrs;
}
export function resolveHomeListenConfig(env = {}) {
    const enableWebRTC = parseEnvFlag(env.ENABLE_WEBRTC, true);
    const bootstrapAddrs = parseCommaList(env.BOOTSTRAP_PEERS);
    const announceHosts = resolveAnnounceHosts(env);
    const listenAddrsOverride = parseCommaList(env.LISTEN_ADDRS);
    if (listenAddrsOverride.length > 0) {
        const hasWs = listenAddrsOverride.some((addr) => addr.includes('/ws'));
        return {
            listenAddrs: listenAddrsOverride,
            tcpPort: firstTcpPort(listenAddrsOverride) ?? DEFAULT_TCP_PORT,
            wsPort: firstWsPort(listenAddrsOverride),
            enableWebSockets: parseEnvFlag(env.ENABLE_WS ?? env.ENABLE_WEBSOCKETS, hasWs),
            enableWebRTC,
            bootstrapAddrs,
            announceHosts
        };
    }
    const tcpPort = parsePort(env.PORT, DEFAULT_TCP_PORT);
    const enableWebSockets = parseEnvFlag(env.ENABLE_WS ?? env.ENABLE_WEBSOCKETS, true);
    const wsPort = enableWebSockets ? parsePort(env.WS_PORT, DEFAULT_WS_PORT) : null;
    if (enableWebSockets && wsPort === tcpPort) {
        throw new Error(`WS_PORT must differ from PORT (both are ${tcpPort})`);
    }
    const listenAddrs = [`/ip4/0.0.0.0/tcp/${tcpPort}`];
    if (enableWebSockets && wsPort !== null) {
        listenAddrs.push(`/ip4/0.0.0.0/tcp/${wsPort}/ws`);
    }
    return {
        listenAddrs,
        tcpPort,
        wsPort,
        enableWebSockets,
        enableWebRTC,
        bootstrapAddrs,
        announceHosts
    };
}
export function resolvePeerKeyFilePath(env = {}, cwd = process.cwd()) {
    const fromEnv = env.DAUP_PEER_KEY_FILE?.trim();
    if (fromEnv) {
        return isAbsolute(fromEnv) ? fromEnv : resolve(cwd, fromEnv);
    }
    return resolve(cwd, DEFAULT_PEER_KEY_FILE);
}
/**
 * Load PRIVATE_KEY from env or a local file. If both are missing, generate once,
 * write the file with restrictive permissions, and reuse it on the next start.
 * Never logs the private key.
 */
export function loadOrCreatePeerKey(options) {
    const fromEnv = options.privateKeyHex?.trim();
    if (fromEnv) {
        assertPrivateKeyHex(fromEnv);
        return {
            privateKeyHex: fromEnv,
            source: 'env',
            keyFilePath: options.keyFilePath,
            created: false
        };
    }
    if (existsSync(options.keyFilePath)) {
        const fromFile = readFileSync(options.keyFilePath, 'utf8').trim();
        if (!fromFile) {
            throw new Error('Peer key file exists but is empty');
        }
        assertPrivateKeyHex(fromFile);
        return {
            privateKeyHex: fromFile,
            source: 'file',
            keyFilePath: options.keyFilePath,
            created: false
        };
    }
    const generated = generateKeyPairHex().privateKey;
    persistPeerKeyFile(options.keyFilePath, generated);
    return {
        privateKeyHex: generated,
        source: 'generated',
        keyFilePath: options.keyFilePath,
        created: true
    };
}
export function loadOrCreatePeerKeyFromEnv(env = {}, cwd = process.cwd()) {
    return loadOrCreatePeerKey({
        privateKeyHex: env.PRIVATE_KEY,
        keyFilePath: resolvePeerKeyFilePath(env, cwd)
    });
}
export function persistPeerKeyFile(keyFilePath, privateKeyHex) {
    const dir = dirname(keyFilePath);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
        chmodSync(dir, 0o700);
    }
    catch {
        // POSIX perms are best-effort (ignored on some platforms)
    }
    const tmpPath = `${keyFilePath}.tmp-${process.pid}`;
    try {
        writeFileSync(tmpPath, `${privateKeyHex}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        try {
            chmodSync(tmpPath, 0o600);
        }
        catch {
            // POSIX perms are best-effort
        }
        renameSync(tmpPath, keyFilePath);
    }
    catch (err) {
        try {
            unlinkSync(tmpPath);
        }
        catch {
            // tmp may not exist if write failed
        }
        throw err;
    }
}
export function listLanIpv4Addresses() {
    const hosts = [];
    for (const addrs of Object.values(networkInterfaces())) {
        for (const addr of addrs ?? []) {
            if (addr.family === 'IPv4' && !addr.internal) {
                hosts.push(addr.address);
            }
        }
    }
    return hosts;
}
export function resolveAnnounceHosts(env = {}, lanHosts = listLanIpv4Addresses()) {
    const explicit = env.ANNOUNCE_HOST?.trim();
    if (explicit) {
        return [explicit];
    }
    return unique(['127.0.0.1', ...lanHosts]);
}
/**
 * Rewrite listen multiaddrs into copy-pasteable BOOTSTRAP_PEERS values.
 * 0.0.0.0 is not dialable; replace it with each announce host.
 */
export function toBootstrapMultiaddrs(listenAddrs, peerId, announceHosts) {
    const hosts = announceHosts.length > 0 ? announceHosts : ['127.0.0.1'];
    const result = [];
    for (const host of hosts) {
        for (const addr of listenAddrs) {
            result.push(ensurePeerIdSuffix(rewriteListenHost(addr, host), peerId));
        }
    }
    return unique(result);
}
export function formatHomeNodeStartBanner(identity) {
    const lines = [
        '[Home] DAUP home / bootstrap seed node is running',
        `[Home] DID: ${identity.did}`,
        `[Home] PeerId: ${identity.peerId}`,
        '[Home] Listen multiaddrs:'
    ];
    for (const addr of identity.listenAddrs) {
        lines.push(`  ${addr}`);
    }
    lines.push('[Home] BOOTSTRAP_PEERS (copy for other nodes):');
    lines.push(`  ${identity.bootstrapPeers.join(',')}`);
    return lines.join('\n');
}
export function parseEnvFlag(value, defaultValue) {
    if (value === undefined || value.trim() === '') {
        return defaultValue;
    }
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) {
        return true;
    }
    if (['0', 'false', 'no', 'off'].includes(normalized)) {
        return false;
    }
    return defaultValue;
}
export function parsePort(value, defaultPort) {
    if (value === undefined || value.trim() === '') {
        return defaultPort;
    }
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Invalid port: expected an integer between 1 and 65535');
    }
    return port;
}
function parseCommaList(value) {
    if (!value) {
        return [];
    }
    return value
        .split(',')
        .map((part) => part.trim())
        .filter(Boolean);
}
function parseTcpPortFromAddr(addr) {
    const match = addr.match(/\/tcp\/(\d+)/);
    if (!match) {
        return undefined;
    }
    return Number(match[1]);
}
function firstTcpPort(addrs) {
    for (const addr of addrs) {
        if (!addr.includes('/ws')) {
            const port = parseTcpPortFromAddr(addr);
            if (port !== undefined) {
                return port;
            }
        }
    }
    return parseTcpPortFromAddr(addrs[0] ?? '');
}
function firstWsPort(addrs) {
    for (const addr of addrs) {
        if (addr.includes('/ws')) {
            return parseTcpPortFromAddr(addr) ?? null;
        }
    }
    return null;
}
function assertPrivateKeyHex(value) {
    if (!/^[0-9a-fA-F]+$/.test(value) || value.length < 64) {
        throw new Error('Invalid peer private key: expected hex-encoded PKCS8 DER');
    }
}
function rewriteListenHost(addr, host) {
    if (isIPv4(host)) {
        return addr
            .replace(/\/ip4\/0\.0\.0\.0\//, `/ip4/${host}/`)
            .replace(/\/ip4\/127\.0\.0\.1\//, `/ip4/${host}/`);
    }
    if (isIPv6(host)) {
        return addr
            .replace(/\/ip6\/::\//, `/ip6/${host}/`)
            .replace(/\/ip4\/0\.0\.0\.0\//, `/ip6/${host}/`);
    }
    return addr
        .replace(/\/ip4\/0\.0\.0\.0\//, `/dns4/${host}/`)
        .replace(/\/ip4\/127\.0\.0\.1\//, `/dns4/${host}/`);
}
function ensurePeerIdSuffix(addr, peerId) {
    if (addr.includes('/p2p/')) {
        return addr;
    }
    return `${addr}/p2p/${peerId}`;
}
function isIPv4(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}
function isIPv6(host) {
    return host.includes(':');
}
function unique(values) {
    return [...new Set(values)];
}
