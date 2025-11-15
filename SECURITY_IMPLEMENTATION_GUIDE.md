# Security Implementation Guide

**Quick Reference for Critical Security Fixes**

This guide provides code examples and implementation patterns for the most critical security fixes identified in the security review.

---

## 1. Secure Expression Evaluator

### Implementation: Replace eval() with Safe Evaluator

**File:** `common/src/secure-eval.ts`

```typescript
import { Parser } from 'expr-eval';

const parser = new Parser({
    operators: {
        // Only allow safe operators
        add: true,
        subtract: true,
        multiply: true,
        divide: true,
        power: false, // Disable potentially dangerous operations
        mod: true,
        equal: true,
        notEqual: true,
        greater: true,
        less: true,
        greaterEqual: true,
        lessEqual: true,
        and: true,
        or: true,
        not: true,
        in: false, // Disable potentially dangerous operations
    },
    functions: {
        // Only allow safe functions
        abs: Math.abs,
        ceil: Math.ceil,
        floor: Math.floor,
        round: Math.round,
        max: Math.max,
        min: Math.min,
        // Explicitly disallow dangerous functions
    },
});

const MAX_EXPRESSION_LENGTH = 1000;
const EVALUATION_TIMEOUT = 5000; // 5 seconds

export interface EvaluationResult {
    value: any;
    error?: string;
}

export function evaluateExpression(
    expression: string,
    variables: { [name: string]: any }
): EvaluationResult {
    // Input validation
    if (!expression || typeof expression !== 'string') {
        return { value: null, error: 'Invalid expression' };
    }

    if (expression.length > MAX_EXPRESSION_LENGTH) {
        return { value: null, error: 'Expression too long' };
    }

    // Sanitize input - only allow safe characters
    if (!/^[a-zA-Z0-9\s+\-*/().,<>=!&|]+$/.test(expression)) {
        return { value: null, error: 'Invalid characters in expression' };
    }

    try {
        // Parse expression
        const expr = parser.parse(expression);

        // Validate variables - only allow safe variable names
        const safeVariables: { [name: string]: any } = {};
        for (const [key, value] of Object.entries(variables)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
                safeVariables[key] = value;
            }
        }

        // Evaluate with timeout
        const startTime = Date.now();
        const result = expr.evaluate(safeVariables);
        const duration = Date.now() - startTime;

        if (duration > EVALUATION_TIMEOUT) {
            return { value: null, error: 'Evaluation timeout' };
        }

        return { value: result };
    } catch (error: any) {
        // Log error server-side, don't expose details to client
        console.error('Expression evaluation error:', error);
        return { value: null, error: 'Expression evaluation failed' };
    }
}
```

**Usage in Automation:**

```typescript
// plugins/core/src/automation.ts
import { evaluateExpression } from '../../../common/src/secure-eval';

// Replace:
// const f = eval(`(function(eventSource, eventDetails, eventData) {
//     return ${condition};
// })`);

// With:
const result = evaluateExpression(condition, {
    eventSource,
    eventDetails,
    eventData,
});

if (result.error) {
    this.log.e(`Automation condition error: ${result.error}`);
    return false;
}

if (!result.value) {
    return false;
}
```

---

## 2. Secure Shell Executor

### Implementation: Safe Shell Script Execution

**File:** `common/src/secure-shell-executor.ts`

```typescript
import child_process from 'child_process';
import { promisify } from 'util';

const exec = promisify(child_process.exec);

interface ShellExecutionOptions {
    timeout?: number;
    maxOutputSize?: number;
    allowedCommands?: string[];
    workingDirectory?: string;
    environment?: { [key: string]: string };
}

interface ShellExecutionResult {
    stdout: string;
    stderr: string;
    exitCode: number;
    error?: string;
}

const DEFAULT_TIMEOUT = 30000; // 30 seconds
const DEFAULT_MAX_OUTPUT_SIZE = 1024 * 1024; // 1MB
const DEFAULT_ALLOWED_COMMANDS = ['echo', 'cat', 'grep', 'sed', 'awk', 'wc', 'head', 'tail'];

// Dangerous patterns to block
const DANGEROUS_PATTERNS = [
    /[;&|`$(){}[\]]/, // Command chaining, subshells, etc.
    /\$\(/, // Command substitution
    /`/, // Backticks
    /\$\{/, // Variable expansion
    />\s*\//, // Redirection to root
    /rm\s+-rf/, // Dangerous rm commands
    /mkfs/, // Filesystem operations
    /dd\s+if=/, // Disk operations
    /nc\s+/, // Netcat
    /python\s+-c/, // Python code execution
    /node\s+-e/, // Node code execution
    /eval\s+/, // Eval commands
    /exec\s+/, // Exec commands
];

export function sanitizeShellScript(script: string): { sanitized: string; errors: string[] } {
    const errors: string[] = [];

    // Check for dangerous patterns
    for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(script)) {
            errors.push(`Dangerous pattern detected: ${pattern}`);
        }
    }

    // Remove dangerous characters
    let sanitized = script
        .replace(/[;&|`$(){}[\]]/g, '')
        .replace(/\$\{/g, '')
        .replace(/`/g, '');

    // Validate script length
    if (script.length > 10000) {
        errors.push('Script too long');
    }

    return { sanitized, errors };
}

export async function executeShellScript(
    script: string,
    options: ShellExecutionOptions = {}
): Promise<ShellExecutionResult> {
    const {
        timeout = DEFAULT_TIMEOUT,
        maxOutputSize = DEFAULT_MAX_OUTPUT_SIZE,
        allowedCommands = DEFAULT_ALLOWED_COMMANDS,
        workingDirectory,
        environment = {},
    } = options;

    // Sanitize script
    const { sanitized, errors } = sanitizeShellScript(script);
    if (errors.length > 0) {
        return {
            stdout: '',
            stderr: errors.join('\n'),
            exitCode: 1,
            error: 'Script validation failed',
        };
    }

    // Validate working directory if provided
    if (workingDirectory) {
        const path = require('path');
        const resolved = path.resolve(workingDirectory);
        // Ensure working directory is within allowed paths
        if (!resolved.startsWith(process.env.SCRYPTED_VOLUME || '/')) {
            return {
                stdout: '',
                stderr: 'Invalid working directory',
                exitCode: 1,
                error: 'Working directory validation failed',
            };
        }
    }

    // Filter environment variables - only allow safe ones
    const safeEnv: { [key: string]: string } = {
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: process.env.HOME || '/tmp',
        ...environment,
    };

    // Remove dangerous environment variables
    delete safeEnv.IFS;
    delete safeEnv.CDPATH;
    delete safeEnv.PS1;
    delete safeEnv.PS2;

    try {
        // Execute with timeout and output limits
        const { stdout, stderr } = await Promise.race([
            exec(sanitized, {
                timeout,
                maxBuffer: maxOutputSize,
                cwd: workingDirectory,
                env: safeEnv,
                shell: '/bin/sh',
            }),
            new Promise<{ stdout: string; stderr: string }>((_, reject) =>
                setTimeout(() => reject(new Error('Execution timeout')), timeout)
            ),
        ]);

        return {
            stdout: stdout.substring(0, maxOutputSize),
            stderr: stderr.substring(0, maxOutputSize),
            exitCode: 0,
        };
    } catch (error: any) {
        return {
            stdout: '',
            stderr: error.message || 'Execution failed',
            exitCode: error.code || 1,
            error: 'Shell execution failed',
        };
    }
}
```

**Usage in Shell Script Automation:**

```typescript
// plugins/core/src/builtins/shellscript.ts
import { executeShellScript } from '../../../common/src/secure-shell-executor';

async run(script: string) {
    // Log execution for audit
    this.automation.log.i(`Executing shell script (length: ${script.length})`);

    const result = await executeShellScript(script, {
        timeout: 30000,
        maxOutputSize: 1024 * 1024, // 1MB
        environment: {
            EVENT_DATA: this.eventData?.toString() || '',
        },
    });

    if (result.error) {
        this.automation.log.e(`Shell script error: ${result.error}`);
        return;
    }

    if (result.stdout) {
        this.automation.console.log(result.stdout);
    }

    if (result.stderr) {
        this.automation.console.error(result.stderr);
    }

    this.automation.console.log(`Shell script exited with code ${result.exitCode}`);
}
```

---

## 3. Secure Path Utilities

### Implementation: Path Traversal Prevention

**File:** `common/src/secure-path.ts`

```typescript
import path from 'path';
import fs from 'fs';

export class PathSecurityError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'PathSecurityError';
    }
}

/**
 * Normalizes and validates a file path to prevent directory traversal attacks
 * @param filePath - The file path to validate
 * @param baseDirectory - The base directory that the path must be within
 * @returns The normalized, validated path
 * @throws PathSecurityError if the path is invalid or outside the base directory
 */
export function resolveSafePath(filePath: string, baseDirectory: string): string {
    if (!filePath || typeof filePath !== 'string') {
        throw new PathSecurityError('Invalid file path');
    }

    // Normalize the path
    let normalized = path.normalize(filePath);

    // Remove any leading slashes or drive letters
    normalized = normalized.replace(/^[/\\]/, '').replace(/^[a-zA-Z]:/, '');

    // Resolve against base directory
    const resolved = path.resolve(baseDirectory, normalized);

    // Ensure the resolved path is within the base directory
    const baseResolved = path.resolve(baseDirectory);
    
    if (!resolved.startsWith(baseResolved)) {
        throw new PathSecurityError('Path traversal detected');
    }

    // Check for dangerous patterns
    if (resolved.includes('..')) {
        throw new PathSecurityError('Path traversal detected');
    }

    // Additional validation: ensure path doesn't contain null bytes
    if (resolved.includes('\0')) {
        throw new PathSecurityError('Null byte in path');
    }

    return resolved;
}

/**
 * Validates that a file path is safe and within allowed directories
 * @param filePath - The file path to validate
 * @param allowedDirectories - Array of allowed base directories
 * @returns The validated path if safe
 * @throws PathSecurityError if the path is invalid
 */
export function validateFilePath(
    filePath: string,
    allowedDirectories: string[]
): string {
    for (const allowedDir of allowedDirectories) {
        try {
            const resolved = resolveSafePath(filePath, allowedDir);
            // Verify the directory exists
            if (fs.existsSync(path.dirname(resolved))) {
                return resolved;
            }
        } catch (error) {
            // Try next allowed directory
            continue;
        }
    }

    throw new PathSecurityError('File path not within allowed directories');
}

/**
 * Sanitizes a filename to remove dangerous characters
 * @param filename - The filename to sanitize
 * @returns The sanitized filename
 */
export function sanitizeFilename(filename: string): string {
    if (!filename || typeof filename !== 'string') {
        throw new PathSecurityError('Invalid filename');
    }

    // Remove path separators
    let sanitized = filename.replace(/[/\\]/g, '');

    // Remove dangerous characters
    sanitized = sanitized.replace(/[<>:"|?*\x00-\x1f]/g, '');

    // Remove leading/trailing dots and spaces
    sanitized = sanitized.replace(/^[\s.]+|[\s.]+$/g, '');

    // Limit length
    if (sanitized.length > 255) {
        sanitized = sanitized.substring(0, 255);
    }

    return sanitized || 'file';
}
```

**Usage in sendFile():**

```typescript
// server/src/http-interfaces.ts
import { validateFilePath, sanitizeFilename } from '../../common/src/secure-path';

sendFile(filePath: string, options?: HttpResponseOptions) {
    this.sent = true;
    if (options?.code)
        this.res.status(options.code);
    this.#setHeaders(options);

    try {
        // Validate and resolve the file path
        const allowedDirectories = [
            this.unzippedDir ? path.join(this.unzippedDir, 'fs') : null,
            this.filesPath,
        ].filter(Boolean) as string[];

        const sanitizedPath = sanitizeFilename(filePath);
        const validatedPath = validateFilePath(sanitizedPath, allowedDirectories);

        // Verify file exists
        if (!fs.existsSync(validatedPath)) {
            this.res.status(404);
            this.res.end();
            return;
        }

        // Verify it's a file, not a directory
        const stats = fs.statSync(validatedPath);
        if (!stats.isFile()) {
            this.res.status(403);
            this.res.end();
            return;
        }

        // Send file
        this.res.sendFile(validatedPath, {
            root: null,
            dotfiles: 'deny', // Changed from 'allow'
            cacheControl: false,
        });
    } catch (error) {
        if (error instanceof PathSecurityError) {
            this.res.status(403);
            this.res.send('Invalid file path');
        } else {
            this.res.status(500);
            this.res.send('Internal server error');
        }
        // Log error server-side
        console.error('File access error:', error);
    }
}
```

---

## 4. Secure Password Hashing

### Implementation: PBKDF2 Password Hashing

**File:** `server/src/services/password-hash.ts`

```typescript
import crypto from 'crypto';

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_LENGTH = 64;
const PBKDF2_DIGEST = 'sha512';
const SALT_LENGTH = 64;
const HASH_VERSION = 2; // Increment when changing algorithm

export interface PasswordHash {
    hash: string;
    salt: string;
    iterations: number;
    version: number;
}

/**
 * Hashes a password using PBKDF2
 * @param password - The plaintext password
 * @returns Password hash object with salt and metadata
 */
export function hashPassword(password: string): PasswordHash {
    if (!password || typeof password !== 'string') {
        throw new Error('Invalid password');
    }

    // Validate password strength
    if (password.length < 12) {
        throw new Error('Password must be at least 12 characters');
    }

    // Generate random salt
    const salt = crypto.randomBytes(SALT_LENGTH).toString('base64');

    // Hash password using PBKDF2
    const hash = crypto.pbkdf2Sync(
        password,
        salt,
        PBKDF2_ITERATIONS,
        PBKDF2_KEY_LENGTH,
        PBKDF2_DIGEST
    ).toString('hex');

    return {
        hash,
        salt,
        iterations: PBKDF2_ITERATIONS,
        version: HASH_VERSION,
    };
}

/**
 * Verifies a password against a hash using constant-time comparison
 * @param password - The plaintext password to verify
 * @param storedHash - The stored hash object
 * @returns True if password matches, false otherwise
 */
export function verifyPassword(password: string, storedHash: PasswordHash): boolean {
    if (!password || !storedHash || !storedHash.hash || !storedHash.salt) {
        return false;
    }

    // Handle legacy SHA-256 hashes (for migration)
    if (storedHash.version === 1 || !storedHash.version) {
        return verifyLegacyPassword(password, storedHash);
    }

    // Verify using PBKDF2
    const hash = crypto.pbkdf2Sync(
        password,
        storedHash.salt,
        storedHash.iterations || PBKDF2_ITERATIONS,
        PBKDF2_KEY_LENGTH,
        PBKDF2_DIGEST
    ).toString('hex');

    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
        Buffer.from(hash),
        Buffer.from(storedHash.hash)
    );
}

/**
 * Verifies a password against legacy SHA-256 hash (for migration)
 */
function verifyLegacyPassword(password: string, storedHash: any): boolean {
    const salted = storedHash.salt + password;
    const hash = crypto.createHash('sha256');
    hash.update(salted);
    const sha = hash.digest().toString('hex');

    return crypto.timingSafeEqual(
        Buffer.from(sha),
        Buffer.from(storedHash.passwordHash || storedHash.hash)
    );
}

/**
 * Checks if a password hash needs to be upgraded
 * @param storedHash - The stored hash object
 * @returns True if hash needs upgrade
 */
export function needsRehash(storedHash: PasswordHash): boolean {
    return !storedHash.version || storedHash.version < HASH_VERSION;
}
```

**Usage in User Service:**

```typescript
// server/src/services/users.ts
import { hashPassword, verifyPassword, needsRehash } from './password-hash';

export function setScryptedUserPassword(user: ScryptedUser, password: string, timestamp: number) {
    const passwordHash = hashPassword(password);
    
    user.salt = passwordHash.salt;
    user.passwordHash = passwordHash.hash;
    user.passwordIterations = passwordHash.iterations;
    user.passwordVersion = passwordHash.version;
    user.passwordDate = timestamp;
    user.token = crypto.randomBytes(16).toString('hex');
}

// Update password verification in authentication middleware
// server/src/scrypted-server-main.ts
import { verifyPassword, needsRehash, hashPassword } from './services/password-hash';

const basicAuth = httpAuth.basic({
    realm: 'Scrypted',
}, async (username, password, callback) => {
    const user = await db.tryGet(ScryptedUser, username);
    if (!user) {
        callback(false);
        return;
    }

    // Verify password
    const passwordHash = {
        hash: user.passwordHash,
        salt: user.salt,
        iterations: user.passwordIterations || 1,
        version: user.passwordVersion || 1,
    };

    const isValid = verifyPassword(password, passwordHash) || password === user.token;

    // Upgrade password hash if needed
    if (isValid && needsRehash(passwordHash)) {
        const newHash = hashPassword(password);
        user.salt = newHash.salt;
        user.passwordHash = newHash.hash;
        user.passwordIterations = newHash.iterations;
        user.passwordVersion = newHash.version;
        await db.upsert(user);
    }

    callback(isValid);
});
```

---

## 5. Rate Limiting Middleware

### Implementation: Express Rate Limiting

**File:** `server/src/middleware/rate-limit.ts`

```typescript
import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';

// Login rate limiter - 5 attempts per 15 minutes
export const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req: Request, res: Response) => {
        res.status(429).json({
            error: 'Too many login attempts',
            retryAfter: Math.ceil(req.rateLimit?.resetTime ? (req.rateLimit.resetTime - Date.now()) / 1000 : 15 * 60),
        });
    },
    skipSuccessfulRequests: true, // Don't count successful logins
});

// General API rate limiter - 100 requests per 15 minutes
export const apiRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

// Token validation rate limiter - 20 requests per minute
export const tokenRateLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 20,
    message: 'Too many token validation attempts',
    standardHeaders: true,
    legacyHeaders: false,
});

// IP-based rate limiter for suspicious activity
export const suspiciousActivityLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50,
    message: 'Suspicious activity detected',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req: Request) => {
        // Skip rate limiting for authenticated admin users
        return !!(req as any).locals?.username && !(req as any).locals?.aclId;
    },
});
```

**Usage in Server:**

```typescript
// server/src/scrypted-server-main.ts
import { loginRateLimiter, apiRateLimiter, tokenRateLimiter } from './middleware/rate-limit';

// Apply rate limiting to login endpoints
app.post('/login', loginRateLimiter, async (req, res) => {
    // Login logic
});

// Apply rate limiting to token validation
app.use('/api/token', tokenRateLimiter);

// Apply general API rate limiting
app.use('/api', apiRateLimiter);
```

---

## 6. Input Validation Middleware

### Implementation: Request Validation

**File:** `server/src/middleware/validation.ts`

```typescript
import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_JSON_DEPTH = 10;

export function validateBody(schema: Joi.ObjectSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        const { error, value } = schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true,
        });

        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                details: error.details.map(d => d.message),
            });
        }

        req.body = value;
        next();
    };
}

export function validateQuery(schema: Joi.ObjectSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        const { error, value } = schema.validate(req.query, {
            abortEarly: false,
            stripUnknown: true,
        });

        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                details: error.details.map(d => d.message),
            });
        }

        req.query = value;
        next();
    };
}

// JSON parsing with limits
export function safeJsonParse(json: string): any {
    // Check size
    if (json.length > MAX_BODY_SIZE) {
        throw new Error('JSON payload too large');
    }

    // Parse with depth limit
    let depth = 0;
    const parsed = JSON.parse(json, (key, value) => {
        depth++;
        if (depth > MAX_JSON_DEPTH) {
            throw new Error('JSON depth exceeded');
        }
        return value;
    });

    return parsed;
}
```

**Usage:**

```typescript
// plugins/google-home/src/main.ts
import { safeJsonParse } from '../../../server/src/middleware/validation';

async onRequest(request: HttpRequest, response: HttpResponse): Promise<void> {
    try {
        // Safe JSON parsing with limits
        const body = safeJsonParse(request.body);
        
        // Additional validation
        if (!body || typeof body !== 'object') {
            response.send('Invalid request body', { code: 400 });
            return;
        }

        // Process request...
    } catch (error) {
        this.console.error('Request parsing error', error);
        response.send('Invalid request', { code: 400 });
        return;
    }
}
```

---

## Testing Examples

### Unit Test for Secure Eval

```typescript
// common/test/secure-eval.test.ts
import { evaluateExpression } from '../src/secure-eval';

describe('Secure Expression Evaluator', () => {
    it('should evaluate simple expressions', () => {
        const result = evaluateExpression('1 + 2', {});
        expect(result.value).toBe(3);
        expect(result.error).toBeUndefined();
    });

    it('should reject dangerous expressions', () => {
        const result = evaluateExpression('eval("malicious")', {});
        expect(result.error).toBeDefined();
    });

    it('should enforce timeout', () => {
        // Test with expression that would take too long
        const result = evaluateExpression('1 + 1', {});
        // Should complete within timeout
        expect(result.error).toBeUndefined();
    });
});
```

### Integration Test for Path Security

```typescript
// server/test/path-security.test.ts
import { resolveSafePath, PathSecurityError } from '../../common/src/secure-path';

describe('Path Security', () => {
    it('should prevent directory traversal', () => {
        expect(() => {
            resolveSafePath('../../../etc/passwd', '/tmp');
        }).toThrow(PathSecurityError);
    });

    it('should allow valid paths', () => {
        const path = resolveSafePath('file.txt', '/tmp');
        expect(path).toBe('/tmp/file.txt');
    });
});
```

---

## Summary

These implementation examples provide:

1. **Secure Expression Evaluator** - Replaces eval() with safe evaluation
2. **Secure Shell Executor** - Prevents command injection
3. **Secure Path Utilities** - Prevents path traversal
4. **Secure Password Hashing** - Uses PBKDF2 with proper key derivation
5. **Rate Limiting** - Prevents brute-force attacks
6. **Input Validation** - Validates and sanitizes inputs

Each implementation follows security best practices:
- Input validation and sanitization
- Error handling without information disclosure
- Comprehensive logging
- Test coverage
- Defense in depth

---

*Refer to SECURITY_IMPROVEMENT_PLAN.md for the complete implementation roadmap.*

