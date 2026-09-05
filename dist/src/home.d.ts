#!/usr/bin/env node
import 'dotenv/config';
import { P2PNode } from './node.js';
export declare function startHomeNode(env?: NodeJS.ProcessEnv): Promise<P2PNode>;
