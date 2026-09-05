#!/usr/bin/env node
import 'dotenv/config';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { P2PNode } from './node.js';
import {
  formatHomeNodeStartBanner,
  loadOrCreatePeerKeyFromEnv,
  resolveHomeListenConfig,
  toBootstrapMultiaddrs
} from './home-config.js';

export async function startHomeNode(env: NodeJS.ProcessEnv = process.env): Promise<P2PNode> {
  const config = resolveHomeListenConfig(env);
  const key = loadOrCreatePeerKeyFromEnv(env);

  if (key.created) {
    console.log(`[Home] Generated peer key and saved to ${key.keyFilePath}`);
  } else if (key.source === 'file') {
    console.log(`[Home] Loaded peer key from ${key.keyFilePath}`);
  } else {
    console.log('[Home] Loaded peer key from PRIVATE_KEY');
  }

  const node = new P2PNode({ privateKeyHex: key.privateKeyHex });
  await node.start({
    listenAddrs: config.listenAddrs,
    bootstrapAddrs: config.bootstrapAddrs,
    enableWebRTC: config.enableWebRTC,
    enableWebSockets: config.enableWebSockets
  });

  const peerId = node.node.peerId.toString();
  const listenAddrs = node.node.getMultiaddrs().map((addr: { toString(): string }) => addr.toString());
  const bootstrapPeers = toBootstrapMultiaddrs(listenAddrs, peerId, config.announceHosts);

  console.log(formatHomeNodeStartBanner({
    did: node.did,
    peerId,
    listenAddrs,
    bootstrapPeers
  }));

  return node;
}

async function main(): Promise<void> {
  const node = await startHomeNode();

  const shutdown = async (signal: string) => {
    console.log(`[Home] Received ${signal}, stopping...`);
    await node.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  return resolve(fileURLToPath(import.meta.url)) === resolve(entry);
}

if (isDirectRun()) {
  main().catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[Home] Failed to start: ${message}`);
    process.exit(1);
  });
}
