/**
 * RPC Buffer Array Serialization Test
 * 
 * Tests serialization and transfer of buffer arrays across RPC
 */

import net from 'net';
import { listenZeroSingleClient } from "../src/listen-zero";
import { createDuplexRpcPeer } from "../src/rpc-serializer";
import { RpcPeer } from '../src/rpc';

describe('RPC Buffer Array Serialization', () => {
    it('should serialize and transfer buffer arrays between peers', async () => {
        const { port, clientPromise } = await listenZeroSingleClient('127.0.0.1');

        const n1 = net.connect({
            port,
            host: '127.0.0.1',
        });

        const n2 = await clientPromise;

        const p1 = createDuplexRpcPeer('p1', 'p2', n1, n1);
        const p2 = createDuplexRpcPeer('p2', 'p1', n2, n2);

        // Create buffer array
        const buffers: Buffer[] = [
            Buffer.alloc(10),
            Buffer.alloc(20),
            Buffer.alloc(30),
        ];

        // Mark for JSON copy serialization
        (buffers as any)[RpcPeer.PROPERTY_JSON_COPY_SERIALIZE_CHILDREN] = true;

        // Set parameter
        p1.params.test = buffers;

        // Retrieve from other peer
        const transferred = await p2.getParam('test') as Buffer[];

        // Verify transfer
        expect(transferred).toBeDefined();
        expect(Array.isArray(transferred)).toBe(true);
        expect(transferred.length).toBe(3);
        expect(transferred[0].length).toBe(10);
        expect(transferred[1].length).toBe(20);
        expect(transferred[2].length).toBe(30);

        // Cleanup
        n1.destroy();
        n2.destroy();
    });

    it('should handle empty buffer arrays', async () => {
        const { port, clientPromise } = await listenZeroSingleClient('127.0.0.1');

        const n1 = net.connect({
            port,
            host: '127.0.0.1',
        });

        const n2 = await clientPromise;

        const p1 = createDuplexRpcPeer('p1', 'p2', n1, n1);
        const p2 = createDuplexRpcPeer('p2', 'p1', n2, n2);

        const emptyBuffers: Buffer[] = [];
        (emptyBuffers as any)[RpcPeer.PROPERTY_JSON_COPY_SERIALIZE_CHILDREN] = true;

        p1.params.test = emptyBuffers;

        const transferred = await p2.getParam('test') as Buffer[];

        expect(transferred).toBeDefined();
        expect(Array.isArray(transferred)).toBe(true);
        expect(transferred.length).toBe(0);

        // Cleanup
        n1.destroy();
        n2.destroy();
    });
});

