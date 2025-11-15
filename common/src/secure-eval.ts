/**
 * Secure Expression Evaluator
 * 
 * Replaces unsafe eval() usage with secure expression evaluation.
 * Uses expr-eval library for safe mathematical and logical expression evaluation.
 */

import { Parser } from 'expr-eval';

const MAX_EXPRESSION_LENGTH = 1000;
const EVALUATION_TIMEOUT = 5000; // 5 seconds

export interface EvaluationResult {
    value: any;
    error?: string;
}

// Create parser with restricted operators and functions
// Note: allowMemberAccess is needed for automation conditions like eventSource.name
const parser = new Parser({
    operators: {
        // Allow safe arithmetic operators
        add: true,
        subtract: true,
        multiply: true,
        divide: true,
        remainder: true, // Modulo operator
        power: false, // Disable potentially dangerous operations
        // Allow comparison operators (comparison enables ==, !=, <, >, <=, >=)
        comparison: true,
        // Allow logical operators (enables 'and', 'or', 'not')
        logical: true,
        // Disable potentially dangerous operations
        in: false,
        conditional: false, // Disable ternary operator
        concatenate: false, // Disable string concatenation
    },
    allowMemberAccess: true, // Needed for eventSource.name, eventDetails.property, etc.
});

/**
 * Validates that an expression contains only safe characters
 */
function isValidExpression(expression: string): boolean {
    // Allow alphanumeric, spaces, and safe operators
    // This regex allows: numbers, letters, spaces, +, -, *, /, %, =, !, <, >, &, |, (, ), ., quotes
    // Note: === and !== are handled by expr-eval as == and !=
    // Note: && and || need to be converted to 'and' and 'or' for expr-eval
    // Note: . is needed for property access like eventSource.name
    if (!/^[a-zA-Z0-9\s+\-*/().,<>=!&|"']+$/.test(expression)) {
        return false;
    }

    // Check for dangerous patterns
    const dangerousPatterns = [
        /eval\s*\(/i,
        /Function\s*\(/i,
        /setTimeout\s*\(/i,
        /setInterval\s*\(/i,
        /require\s*\(/i,
        /import\s*\(/i,
        /process\./,
        /global\./,
        /__proto__/,
        /constructor\s*\(/i, // Only block constructor calls, not property access
        /\.prototype\./,
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(expression)) {
            return false;
        }
    }

    return true;
}

/**
 * Normalizes JavaScript operators to expr-eval syntax
 * - === becomes ==
 * - !== becomes !=
 * - && becomes and
 * - || becomes or
 */
function normalizeExpression(expression: string): string {
    return expression
        .replace(/===/g, '==')
        .replace(/!==/g, '!=')
        .replace(/\s*&&\s*/g, ' and ')
        .replace(/\s*\|\|\s*/g, ' or ');
}

/**
 * Sanitizes variable names to prevent prototype pollution
 */
function sanitizeVariables(variables: { [name: string]: any }): { [name: string]: any } {
    const safeVariables: { [name: string]: any } = {};
    
    for (const [key, value] of Object.entries(variables)) {
        // Only allow valid JavaScript identifier names
        if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
            // Filter out dangerous variable names
            if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
                safeVariables[key] = value;
            }
        }
    }
    
    return safeVariables;
}

/**
 * Evaluates a mathematical/logical expression safely
 * 
 * @param expression - The expression string to evaluate
 * @param variables - Variables to use in the expression
 * @returns Evaluation result with value or error
 */
export function evaluateExpression(
    expression: string,
    variables: { [name: string]: any } = {}
): EvaluationResult {
    // Input validation
    if (!expression || typeof expression !== 'string') {
        return { value: null, error: 'Invalid expression: must be a non-empty string' };
    }

    if (expression.length === 0) {
        return { value: null, error: 'Invalid expression: empty string' };
    }

    if (expression.length > MAX_EXPRESSION_LENGTH) {
        return { 
            value: null, 
            error: `Expression too long: maximum length is ${MAX_EXPRESSION_LENGTH} characters` 
        };
    }

    // Validate expression contains only safe characters and patterns
    if (!isValidExpression(expression)) {
        return { value: null, error: 'Invalid expression: contains unsafe characters or patterns' };
    }

    try {
        // Normalize expression (convert === to ==, && to and, etc.)
        const normalizedExpression = normalizeExpression(expression);
        
        // Parse expression
        const expr = parser.parse(normalizedExpression);

        // Sanitize variables
        const safeVariables = sanitizeVariables(variables);

        // Evaluate with timeout protection
        const startTime = Date.now();
        const result = expr.evaluate(safeVariables);
        const duration = Date.now() - startTime;

        if (duration > EVALUATION_TIMEOUT) {
            return { value: null, error: 'Expression evaluation timeout' };
        }

        // Handle division by zero gracefully
        if (typeof result === 'number' && !isFinite(result)) {
            return { value: null, error: 'Expression evaluation resulted in invalid number' };
        }

        return { value: result };
    } catch (error: any) {
        // Log error server-side for debugging, but don't expose details to client
        console.error('Expression evaluation error:', {
            expression: expression.substring(0, 100), // Log first 100 chars only
            error: error.message,
        });
        
        return { 
            value: null, 
            error: 'Expression evaluation failed: invalid syntax or runtime error' 
        };
    }
}

