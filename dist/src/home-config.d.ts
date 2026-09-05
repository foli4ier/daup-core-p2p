export declare const DEFAULT_TCP_PORT = 4001;
export declare const DEFAULT_WS_PORT = 4002;
export declare const DEFAULT_PEER_KEY_FILE = ".daup/peer.key";
export type EnvMap = Record<string, string | undefined>;
export interface HomeListenConfig {
    listenAddrs: string[];
    tcpPort: number;
    wsPort: number | null;
    enableWebSockets: boolean;
    enableWebRTC: boolean;
    bootstrapAddrs: string[];
    announceHosts: string[];
}
export interface LoadPeerKeyResult {
    privateKeyHex: string;
    source: 'env' | 'file' | 'generated';
    keyFilePath: string;
    created: boolean;
}
export interface HomeNodeIdentity {
    did: string;
    peerId: string;
    listenAddrs: string[];
    bootstrapPeers: string[];
}
/**
 * Parse PORT / WS_PORT / LISTEN_ADDRS for the always-on home / seed profile.
 * LISTEN_ADDRS (comma-separated) wins when set.
 */
export declare function parseListenAddrs(env?: EnvMap): string[];
export declare function resolveHomeListenConfig(env?: EnvMap): HomeListenConfig;
export declare function resolvePeerKeyFilePath(env?: EnvMap, cwd?: string): string;
/**
 * Load PRIVATE_KEY from env or a local file. If both are missing, generate once,
 * write the file with restrictive permissions, and reuse it on the next start.
 * Never logs the private key.
 */
export declare function loadOrCreatePeerKey(options: {
    privateKeyHex?: string;
    keyFilePath: string;
}): LoadPeerKeyResult;
export declare function loadOrCreatePeerKeyFromEnv(env?: EnvMap, cwd?: string): LoadPeerKeyResult;
export declare function persistPeerKeyFile(keyFilePath: string, privateKeyHex: string): void;
export declare function listLanIpv4Addresses(): string[];
export declare function resolveAnnounceHosts(env?: EnvMap, lanHosts?: string[]): string[];
/**
 * Rewrite listen multiaddrs into copy-pasteable BOOTSTRAP_PEERS values.
 * 0.0.0.0 is not dialable; replace it with each announce host.
 */
export declare function toBootstrapMultiaddrs(listenAddrs: string[], peerId: string, announceHosts: string[]): string[];
export declare function formatHomeNodeStartBanner(identity: HomeNodeIdentity): string;
export declare function parseEnvFlag(value: string | undefined, defaultValue: boolean): boolean;
export declare function parsePort(value: string | undefined, defaultPort: number): number;
