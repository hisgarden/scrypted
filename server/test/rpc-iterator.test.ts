/**
 * RPC Iterator/Generator Test
 * 
 * Tests async generator/iterator handling across RPC
 */

import { RpcPeer } from "../src/rpc";
import { sleep } from '../src/sleep';

describe('RPC Iterator/Generator', () => {
    it('should transfer and iterate async generators between peers', async () => {
        const p1 = new RpcPeer('p1', 'p2', message => {
            p2.handleMessage(message);
        });

        const p2 = new RpcPeer('p2', 'p1', message => {
            p1.handleMessage(message);
        });

        async function* generator() {
            try {
                yield 2;
                yield 3;
                yield 4;
            }
            catch (e) {
                // Handle errors
            }
        }

        p1.params['thing'] = generator();

        const foo = await p2.getParam('thing') as AsyncGenerator<number>;

        expect(foo).toBeDefined();

        const results: number[] = [];
        for await (const c of foo) {
            results.push(c);
        }

        expect(results).toEqual([2, 3, 4]);
    });

    it('should handle generator next() calls', async () => {
        const p1 = new RpcPeer('p1', 'p2', message => {
            p2.handleMessage(message);
        });

        const p2 = new RpcPeer('p2', 'p1', message => {
            p1.handleMessage(message);
        });

        async function* generator() {
            yield 1;
            yield 2;
        }

        p1.params['thing'] = generator();

        const foo = await p2.getParam('thing') as AsyncGenerator<number>;

        const first = await foo.next();
        expect(first.value).toBe(1);
        expect(first.done).toBe(false);

        await sleep(0);

        const second = await foo.next();
        expect(second.value).toBe(2);
        expect(second.done).toBe(false);

        await sleep(0);

        const third = await foo.next();
        expect(third.done).toBe(true);
    });

    it('should handle generator return() calls', async () => {
        const p1 = new RpcPeer('p1', 'p2', message => {
            p2.handleMessage(message);
        });

        const p2 = new RpcPeer('p2', 'p1', message => {
            p1.handleMessage(message);
        });

        async function* generator() {
            try {
                yield 1;
                yield 2;
            }
            finally {
                // Cleanup
            }
        }

        p1.params['thing'] = generator();

        const foo = await p2.getParam('thing') as AsyncGenerator<number>;

        const first = await foo.next();
        expect(first.value).toBe(1);

        await sleep(0);

        const returned = await foo.return(44);
        // Note: return() may not preserve the value across RPC, but done should be true
        expect(returned.done).toBe(true);

        await sleep(0);

        const afterReturn = await foo.next();
        expect(afterReturn.done).toBe(true);
    });
});

