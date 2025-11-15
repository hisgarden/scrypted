/**
 * RPC Duplex Communication Test
 * 
 * Tests bidirectional RPC communication between two peers
 */

import net from 'net';
import { listenZeroSingleClient } from "../src/listen-zero";
import { createDuplexRpcPeer } from "../src/rpc-serializer";

describe('RPC Duplex Communication', () => {
    it('should establish bidirectional communication between two peers', async () => {
        const { port, clientPromise } = await listenZeroSingleClient('127.0.0.1');

        const n1 = net.connect({
            port,
            host: '127.0.0.1',
        });

        const n2 = await clientPromise;

        const p1 = createDuplexRpcPeer('p1', 'p2', n1, n1);
        const p2 = createDuplexRpcPeer('p2', 'p1', n2, n2);

        // Set up test functions
        const p1TestCalled = jest.fn(() => 'p1 test');
        const p2TestCalled = jest.fn(() => 'p2 test');

        p1.params.test = p1TestCalled;
        p2.params.test = p2TestCalled;

        // Call functions across RPC
        const p1TestFunc = await p1.getParam('test');
        const p2TestFunc = await p2.getParam('test');

        expect(p1TestFunc).toBeDefined();
        expect(p2TestFunc).toBeDefined();

        // Cleanup
        n1.destroy();
        n2.destroy();
    });

    it('should handle parameter passing between peers', async () => {
        const { port, clientPromise } = await listenZeroSingleClient('127.0.0.1');

        const n1 = net.connect({
            port,
            host: '127.0.0.1',
        });

        const n2 = await clientPromise;

        const p1 = createDuplexRpcPeer('p1', 'p2', n1, n1);
        const p2 = createDuplexRpcPeer('p2', 'p1', n2, n2);

        // Set up a parameter
        const testValue = 'test-parameter';
        p1.params.testParam = testValue;

        // Retrieve parameter from other peer
        const retrieved = await p2.getParam('testParam');

        expect(retrieved).toBe(testValue);

        // Cleanup
        n1.destroy();
        n2.destroy();
    });
});

