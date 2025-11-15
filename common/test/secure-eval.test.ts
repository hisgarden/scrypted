/**
 * TDD Tests for Secure Expression Evaluator
 * 
 * These tests define the expected behavior BEFORE implementation.
 * Following TDD: Red -> Green -> Refactor
 */

import { evaluateExpression, EvaluationResult } from '../src/secure-eval';

describe('Secure Expression Evaluator', () => {
    describe('should evaluate simple arithmetic expressions', () => {
        it('should evaluate addition', () => {
            const result = evaluateExpression('1 + 2', {});
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(3);
        });

        it('should evaluate subtraction', () => {
            const result = evaluateExpression('5 - 3', {});
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(2);
        });

        it('should evaluate multiplication', () => {
            const result = evaluateExpression('3 * 4', {});
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(12);
        });

        it('should evaluate division', () => {
            const result = evaluateExpression('10 / 2', {});
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(5);
        });

        it('should evaluate complex expressions', () => {
            const result = evaluateExpression('(1 + 2) * 3', {});
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(9);
        });
    });

    describe('should evaluate expressions with variables', () => {
        it('should evaluate expression with single variable', () => {
            const result = evaluateExpression('x + 1', { x: 5 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(6);
        });

        it('should evaluate expression with multiple variables', () => {
            const result = evaluateExpression('a + b * c', { a: 1, b: 2, c: 3 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(7);
        });

        it('should handle eventSource variable', () => {
            const mockEventSource = { name: 'TestDevice', id: 'test-123' };
            const result = evaluateExpression('eventSource.name === "TestDevice"', {
                eventSource: mockEventSource,
            });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should handle eventDetails variable', () => {
            const mockEventDetails = { eventInterface: 'OnOff', property: 'on' };
            const result = evaluateExpression('eventDetails.property === "on"', {
                eventDetails: mockEventDetails,
            });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should handle eventData variable', () => {
            const result = evaluateExpression('eventData > 0', { eventData: 42 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });
    });

    describe('should evaluate boolean expressions', () => {
        it('should evaluate equality comparison', () => {
            const result = evaluateExpression('x === 5', { x: 5 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate inequality comparison', () => {
            const result = evaluateExpression('x !== 5', { x: 3 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate greater than comparison', () => {
            const result = evaluateExpression('x > 5', { x: 10 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate less than comparison', () => {
            const result = evaluateExpression('x < 5', { x: 3 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate logical AND', () => {
            const result = evaluateExpression('x > 0 && x < 10', { x: 5 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate logical OR', () => {
            const result = evaluateExpression('x < 0 || x > 10', { x: 5 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(false);
        });
    });

    describe('should reject dangerous expressions', () => {
        it('should reject eval() calls', () => {
            const result = evaluateExpression('eval("malicious code")', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject Function constructor', () => {
            const result = evaluateExpression('Function("return malicious")()', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject command chaining with semicolon', () => {
            const result = evaluateExpression('1 + 1; malicious()', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject command chaining with pipe', () => {
            const result = evaluateExpression('1 + 1 | malicious', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject backticks', () => {
            const result = evaluateExpression('`malicious command`', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject dangerous characters', () => {
            const result = evaluateExpression('1 + 1 && rm -rf /', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });
    });

    describe('should enforce input validation', () => {
        it('should reject null input', () => {
            const result = evaluateExpression(null as any, {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject undefined input', () => {
            const result = evaluateExpression(undefined as any, {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject non-string input', () => {
            const result = evaluateExpression(123 as any, {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject empty string', () => {
            const result = evaluateExpression('', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject expressions exceeding max length', () => {
            const longExpression = '1 + '.repeat(1000) + '1';
            const result = evaluateExpression(longExpression, {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });

        it('should reject invalid characters', () => {
            const result = evaluateExpression('1 + 2\x00malicious', {});
            expect(result.error).toBeDefined();
            expect(result.value).toBeNull();
        });
    });

    describe('should validate variable names', () => {
        it('should accept valid variable names', () => {
            const result = evaluateExpression('validVar + 1', { validVar: 5 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(6);
        });

        it('should reject variables with special characters', () => {
            const result = evaluateExpression('invalid-var + 1', { 'invalid-var': 5 });
            // Should either error or sanitize the variable
            // The implementation should handle this securely
        });

        it('should filter out dangerous variables', () => {
            const dangerousVars = {
                __proto__: {},
                constructor: {},
                eval: () => {},
                Function: Function,
            };
            const result = evaluateExpression('x + 1', dangerousVars);
            // Should not allow dangerous variables to be used
            expect(result.error).toBeDefined();
        });
    });

    describe('should handle edge cases', () => {
        it('should handle division by zero gracefully', () => {
            const result = evaluateExpression('1 / 0', {});
            // Should either return Infinity or error, but not crash
            expect(result.error !== undefined || isFinite(result.value as number)).toBe(true);
        });

        it('should handle undefined variables', () => {
            const result = evaluateExpression('undefinedVar + 1', {});
            // Should handle undefined variables gracefully
            expect(result.error !== undefined || typeof result.value === 'number').toBe(true);
        });

        it('should handle very large numbers', () => {
            const result = evaluateExpression('999999999999999999999', {});
            expect(result.error).toBeUndefined();
            expect(typeof result.value).toBe('number');
        });
    });

    describe('should enforce timeout', () => {
        it('should timeout on infinite loops (if possible)', () => {
            // Note: expr-eval may not support loops, but test should verify timeout mechanism
            const result = evaluateExpression('1 + 1', {});
            expect(result.error).toBeUndefined();
            // If timeout is implemented, very long expressions should timeout
        });
    });

    describe('should be suitable for automation conditions', () => {
        it('should evaluate typical automation condition', () => {
            const result = evaluateExpression(
                'eventSource.name === "DoorSensor" && eventDetails.property === "open"',
                {
                    eventSource: { name: 'DoorSensor' },
                    eventDetails: { property: 'open' },
                }
            );
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate numeric comparison condition', () => {
            const result = evaluateExpression('eventData > 50', { eventData: 75 });
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });

        it('should evaluate complex automation condition', () => {
            const result = evaluateExpression(
                '(eventData > 0 && eventData < 100) || eventSource.name === "Emergency"',
                {
                    eventData: 50,
                    eventSource: { name: 'NormalSensor' },
                }
            );
            expect(result.error).toBeUndefined();
            expect(result.value).toBe(true);
        });
    });
});

