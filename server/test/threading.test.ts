/**
 * Threading Test
 * 
 * Tests worker thread execution and parameter passing
 */

import worker_threads from 'worker_threads';
import { newThread } from "../src/threading";

describe('Threading', () => {
    it('should execute function in worker thread with parameters', async () => {
        const foo = 5;
        const bar = 6;

        const result = await newThread({
            foo, bar,
        }, async () => {
            return foo + bar;
        });

        expect(result).toBe(11);
    });

    it('should pass parameters to thread function', async () => {
        const foo = 10;
        const bar = 20;

        const result = await newThread({
            foo, bar,
        }, async ({ foo, bar }) => {
            return foo + bar;
        });

        expect(result).toBe(30);
    });

    it('should execute function in worker thread context', async () => {
        let functionCalled = false;

        const sayHelloInMainThread = () => {
            functionCalled = true;
            // This should be called from worker thread, but executed in main thread
        };

        await newThread({
            sayHelloInMainThread,
        }, async () => {
            // This should run in worker thread
            // Call the function passed from main thread
            sayHelloInMainThread();
        });

        // Verify function was called
        expect(functionCalled).toBe(true);
    });

    it('should handle complex calculations in worker thread', async () => {
        const a = 100;
        const b = 200;

        const result = await newThread({
            a, b,
        }, async ({ a, b }) => {
            // Perform calculation in worker thread
            return a * b + (a + b);
        });

        expect(result).toBe(100 * 200 + (100 + 200));
        expect(result).toBe(20300);
    });
});

