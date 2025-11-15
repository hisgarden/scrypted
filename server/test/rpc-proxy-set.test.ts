/**
 * RPC Proxy Set Test
 * 
 * Tests proxy object property setting across RPC
 */

import { RpcPeer } from "../src/rpc";

describe('RPC Proxy Set', () => {
    it('should allow setting properties on proxied objects', async () => {
        const p1 = new RpcPeer('p1', 'p2', message => {
            p2.handleMessage(message);
        });

        const p2 = new RpcPeer('p2', 'p1', message => {
            p1.handleMessage(message);
        });

        class Foo {
            bar?: number;
        }

        p1.params['thing'] = new Foo();

        const foo = await p2.getParam('thing') as Foo;

        // Set property on proxied object
        foo.bar = 3;

        // Verify property was set
        expect(foo.bar).toBe(3);
    });

    it('should handle multiple property sets', async () => {
        const p1 = new RpcPeer('p1', 'p2', message => {
            p2.handleMessage(message);
        });

        const p2 = new RpcPeer('p2', 'p1', message => {
            p1.handleMessage(message);
        });

        class TestClass {
            prop1?: string;
            prop2?: number;
            prop3?: boolean;
        }

        p1.params['thing'] = new TestClass();

        const obj = await p2.getParam('thing') as TestClass;

        obj.prop1 = 'test';
        obj.prop2 = 42;
        obj.prop3 = true;

        expect(obj.prop1).toBe('test');
        expect(obj.prop2).toBe(42);
        expect(obj.prop3).toBe(true);
    });
});

