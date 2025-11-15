# Security Review - Scrypted Repository

**Date:** 2025-11-14  
**Reviewer:** Security Assessment  
**Scope:** Full codebase security review focusing on OWASP Top 10 and common vulnerabilities

---

## Executive Summary

This security review identifies several critical and high-severity security issues that should be addressed to improve the overall security posture of the Scrypted application. The review covers authentication, authorization, input validation, code injection, command injection, path traversal, and other common security vulnerabilities.

---

## Critical Findings

### 1. **Command Injection Vulnerability in Shell Script Execution**

**Severity:** CRITICAL  
**Location:** `plugins/core/src/builtins/shellscript.ts:17-28`

**Issue:**
The `AutomationShellScript.run()` method executes shell scripts without proper sanitization. User-controlled script content is directly piped to a shell process.

```17:28:plugins/core/src/builtins/shellscript.ts
async run(script: string) {
    const cp = child_process.spawn('sh', {
        env: {
            EVENT_DATA: this.eventData?.toString(),
        },
    });
    cp.stdin.write(script);
    cp.stdin.end();
    cp.stdout.on('data', data => this.automation.console.log(data.toString()));
    cp.stderr.on('data', data => this.automation.console.error(data.toString()));
    cp.on('exit', () => this.automation.console.log('shell exited'));
}
```

**Risk:** An attacker with access to automation configuration could execute arbitrary shell commands, potentially leading to remote code execution.

**Recommendation:**
- Implement strict input validation and sanitization
- Use a whitelist of allowed commands
- Consider using a restricted shell environment
- Implement command execution timeouts
- Log all shell script executions for audit purposes

---

### 2. **Code Injection via eval() in Automation Conditions**

**Severity:** CRITICAL  
**Location:** `plugins/core/src/automation.ts:575`

**Issue:**
User-controlled condition strings are executed using `eval()` without proper sanitization.

```575:577:plugins/core/src/automation.ts
const f = eval(`(function(eventSource, eventDetails, eventData) {
    return ${condition};
})`);
```

**Risk:** An attacker could inject malicious JavaScript code that executes with full application privileges.

**Recommendation:**
- Replace `eval()` with a safe expression evaluator (e.g., `expr-eval`, `mathjs`)
- Implement strict input validation
- Use a sandboxed execution environment (e.g., `vm2` with restricted context)
- Consider using a domain-specific language (DSL) for conditions

---

### 3. **Path Traversal Vulnerability in sendFile()**

**Severity:** HIGH  
**Location:** `server/src/http-interfaces.ts:45-70`

**Issue:**
The `sendFile()` method accepts user-controlled paths and may allow directory traversal attacks.

```45:70:server/src/http-interfaces.ts
sendFile(path: string, options?: HttpResponseOptions) {
    this.sent = true;
    if (options?.code)
        this.res.status(options.code);
    this.#setHeaders(options);

    let filePath = pathJoin(this.unzippedDir, 'fs', path);
    if (!fs.existsSync(filePath)) {
        filePath = pathJoin(this.filesPath, path);
        if (!fs.existsSync(filePath)) {
            filePath = path;
            if (!fs.existsSync(filePath)) {
                this.res.status(404);
                this.res.end();
                return;
            }
        }
    }

    // prefer etag
    this.res.sendFile(filePath, {
        root: null,
        dotfiles: 'allow',
        cacheControl: false,
    });
}
```

**Risk:** An attacker could access sensitive files outside the intended directories using `../` sequences.

**Recommendation:**
- Normalize and validate all file paths
- Use `path.resolve()` and ensure paths stay within allowed directories
- Implement path validation: `if (!filePath.startsWith(allowedBasePath)) throw Error('Invalid path')`
- Remove the fallback to absolute paths (`filePath = path`)
- Consider using a whitelist of allowed file patterns

---

### 4. **Weak Password Hashing Algorithm**

**Severity:** HIGH  
**Location:** `server/src/services/users.ts:81-86`

**Issue:**
Passwords are hashed using SHA-256, which is vulnerable to rainbow table attacks and lacks proper key derivation.

```81:86:server/src/services/users.ts
export function setScryptedUserPassword(user: ScryptedUser, password: string, timestamp: number) {
    user.salt = crypto.randomBytes(64).toString('base64');
    user.passwordHash = crypto.createHash('sha256').update(user.salt + password).digest().toString('hex');
    user.passwordDate = timestamp;
    user.token = crypto.randomBytes(16).toString('hex');
}
```

**Risk:** 
- SHA-256 is fast and vulnerable to brute-force attacks
- No key stretching (PBKDF2, bcrypt, Argon2)
- Potential for rainbow table attacks despite salting

**Recommendation:**
- Use `crypto.pbkdf2()` or `bcrypt` for password hashing
- Implement proper key derivation with high iteration counts (100,000+)
- Consider using `scrypt` or `Argon2` for better security
- Example: `crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512')`

---

### 5. **Insecure Token Storage in Query Parameters**

**Severity:** HIGH  
**Location:** `server/src/scrypted-server-main.ts:334-336`

**Issue:**
Authentication tokens are accepted via URL query parameters, which can be logged in server logs, browser history, and referrer headers.

```334:336:server/src/scrypted-server-main.ts
else if (req.query['scryptedToken']) {
    checkToken(req.query.scryptedToken.toString());
}
```

**Risk:**
- Tokens exposed in logs, browser history, and referrer headers
- Potential token leakage through HTTP referrer headers
- Tokens visible in URL bar

**Recommendation:**
- Remove token support from query parameters
- Only accept tokens via Authorization header or secure cookies
- Implement token rotation on exposure detection
- Add logging for token access attempts via query parameters

---

### 6. **Insufficient Input Validation on JSON Parsing**

**Severity:** HIGH  
**Location:** Multiple locations (e.g., `plugins/google-home/src/main.ts:616`, `plugins/alexa/src/main.ts:647`)

**Issue:**
JSON parsing is performed without proper error handling or size limits, potentially leading to DoS attacks.

```616:616:plugins/google-home/src/main.ts
const body = JSON.parse(request.body);
```

**Risk:**
- Large JSON payloads can cause memory exhaustion
- Malformed JSON can crash the application
- No size limits on request bodies

**Recommendation:**
- Implement request body size limits (e.g., `body-parser` with `limit` option)
- Add try-catch blocks around JSON parsing
- Validate JSON structure before processing
- Consider using `JSON.parse()` with reviver function for validation

---

### 7. **CORS Configuration Allows Arbitrary Origins**

**Severity:** MEDIUM-HIGH  
**Location:** `server/src/runtime.ts:199-218`

**Issue:**
CORS origins are dynamically added from environment variables and plugin configurations without proper validation.

```199:218:server/src/runtime.ts
getAccessControlAllowOrigin(headers: http.IncomingHttpHeaders) {
    let { origin, referer } = headers;
    if (!origin && referer) {
        try {
            const u = new URL(headers.referer)
            origin = u.origin;
        }
        catch (e) {
            return;
        }
    }
    if (!origin)
        return;
    const servers: string[] = process.env.SCRYPTED_ACCESS_CONTROL_ALLOW_ORIGINS?.split(',') || [];
    servers.push(...Object.values(this.corsControl.origins).flat());
    if (!servers.includes(origin))
        return;

    return origin;
}
```

**Risk:**
- Plugins can add arbitrary CORS origins
- No validation of origin format
- Potential for CORS misconfiguration attacks

**Recommendation:**
- Validate origin format (must be valid URL)
- Implement origin whitelist validation
- Restrict plugin ability to modify CORS origins
- Add logging for CORS origin additions
- Consider using a more restrictive CORS policy by default

---

### 8. **Error Messages May Leak Sensitive Information**

**Severity:** MEDIUM  
**Location:** Multiple locations

**Issue:**
Error messages are sent directly to clients without sanitization, potentially exposing internal system information.

**Examples:**
- `server/src/plugin/plugin-http.ts:126-129` - Error messages sent directly
- `plugins/google-home/src/main.ts:608` - Error messages exposed

**Risk:**
- Stack traces may reveal file paths, internal structure
- Error messages may expose system configuration
- Information disclosure aids attackers

**Recommendation:**
- Implement centralized error handling
- Sanitize error messages before sending to clients
- Log detailed errors server-side only
- Return generic error messages to clients
- Use error codes instead of detailed messages

---

### 9. **Insecure Default Authentication**

**Severity:** MEDIUM  
**Location:** `server/src/scrypted-server-main.ts:239-255`

**Issue:**
Default authentication can be enabled via environment variable, potentially allowing unauthorized access.

```239:255:server/src/scrypted-server-main.ts
const getDefaultAuthentication = async (req: Request) => {
    const defaultAuthentication = !req.query.disableDefaultAuthentication && process.env.SCRYPTED_DEFAULT_AUTHENTICATION;
    if (!defaultAuthentication)
        return;

    // ... authentication logic
}
```

**Risk:**
- Default authentication may bypass proper security controls
- Relies on referer header validation which can be spoofed
- May allow unauthorized access in misconfigured environments

**Recommendation:**
- Disable default authentication by default
- Require explicit opt-in with strong warnings
- Implement additional validation beyond referer checks
- Document security implications clearly
- Consider removing this feature entirely

---

### 10. **IP-Based Authentication Vulnerable to Spoofing**

**Severity:** MEDIUM  
**Location:** `server/src/scrypted-server-main.ts:260-267`

**Issue:**
IP-based authentication relies on `remoteAddress` which can be spoofed through proxies.

```260:267:server/src/scrypted-server-main.ts
if (process.env.SCRYPTED_ADMIN_USERNAME
    && process.env.SCRYPTED_ADMIN_ADDRESS
    && req.socket.remoteAddress?.endsWith(process.env.SCRYPTED_ADMIN_ADDRESS)) {
    res.locals.username = process.env.SCRYPTED_ADMIN_USERNAME;
    res.locals.aclId = undefined;
    next();
    return;
}
```

**Risk:**
- IP addresses can be spoofed
- X-Forwarded-For headers not validated
- No protection against IP spoofing attacks

**Recommendation:**
- Do not rely solely on IP-based authentication
- If used, validate X-Forwarded-For headers properly
- Implement additional authentication factors
- Use proper reverse proxy configuration
- Document security limitations

---

### 11. **No Rate Limiting on Authentication Endpoints**

**Severity:** MEDIUM  
**Location:** Authentication middleware throughout

**Issue:**
No rate limiting is implemented on login endpoints or token validation endpoints.

**Risk:**
- Brute-force attacks on passwords
- Token enumeration attacks
- DoS attacks on authentication endpoints

**Recommendation:**
- Implement rate limiting (e.g., `express-rate-limit`)
- Add exponential backoff for failed login attempts
- Implement account lockout after multiple failures
- Monitor and alert on suspicious authentication patterns
- Use CAPTCHA for repeated failures

---

### 12. **Environment Variable Exposure**

**Severity:** MEDIUM  
**Location:** `server/src/services/info.ts:10-12`

**Issue:**
All `SCRYPTED_*` environment variables are exposed via an info endpoint.

```10:12:server/src/services/info.ts
for (const key of Object.keys(process.env)) {
    if (key.startsWith('SCRYPTED_'))
        ret[key] = process.env[key];
}
```

**Risk:**
- Sensitive configuration exposed
- Potential information disclosure
- May reveal internal system structure

**Recommendation:**
- Filter sensitive environment variables
- Implement access control on info endpoint
- Only expose non-sensitive configuration
- Use a whitelist of safe environment variables
- Consider removing this endpoint or restricting access

---

### 13. **Insecure File Operations**

**Severity:** MEDIUM  
**Location:** `plugins/prebuffer-mixin/src/file-rtsp-server.ts:36-90`

**Issue:**
File paths are constructed from HTTP headers without proper validation.

```36:40:plugins/prebuffer-mixin/src/file-rtsp-server.ts
async write(url: string, requestHeaders: Headers) {
    const recordingFile = requestHeaders['x-scrypted-rtsp-file'];

    if (!recordingFile)
        return this.respond(400, 'Bad Request', requestHeaders, {});
```

**Risk:**
- Path traversal attacks
- Overwriting critical system files
- Unauthorized file access

**Recommendation:**
- Validate and sanitize file paths from headers
- Restrict file operations to specific directories
- Implement path normalization
- Use whitelist of allowed file patterns
- Add file operation logging

---

### 14. **Weak Token Validation**

**Severity:** MEDIUM  
**Location:** `server/src/scrypted-server-main.ts:273-311`

**Issue:**
Token validation uses simple SHA-256 hashing without proper timing attack protection.

**Risk:**
- Timing attacks on token validation
- Weak token generation
- No token expiration enforcement

**Recommendation:**
- Use constant-time comparison for token validation
- Implement proper token expiration
- Use cryptographically secure random token generation
- Consider using JWT with proper signing

---

### 15. **No HTTPS Enforcement**

**Severity:** MEDIUM  
**Location:** Server configuration

**Issue:**
Application runs on both HTTP and HTTPS ports without enforcing HTTPS.

**Risk:**
- Man-in-the-middle attacks
- Credential interception
- Session hijacking

**Recommendation:**
- Enforce HTTPS for all sensitive operations
- Implement HSTS headers
- Redirect HTTP to HTTPS
- Use secure cookies only
- Consider disabling HTTP port in production

---

## Positive Security Practices Found

1. **Self-Signed Certificate Management:** Proper certificate generation and management
2. **Cookie Signing:** Cookies are signed using SHA-256 hash of private key
3. **Database Abstraction:** Uses LevelDB with proper abstraction layer
4. **Plugin Isolation:** Plugins run in separate processes/workers
5. **RPC Security:** Cluster object connections use hash verification
6. **WebSocket Security:** Proper CORS handling for WebSocket connections

---

## Recommendations Summary

### Immediate Actions (Critical/High)
1. Replace `eval()` with safe expression evaluator
2. Implement proper password hashing (PBKDF2/bcrypt/Argon2)
3. Fix path traversal vulnerabilities
4. Remove token support from query parameters
5. Add input validation and sanitization for shell scripts
6. Implement request body size limits

### Short-term Actions (Medium)
1. Implement rate limiting on authentication endpoints
2. Add proper error handling and sanitization
3. Fix CORS configuration validation
4. Remove or secure environment variable exposure
5. Implement HTTPS enforcement
6. Add file operation validation

### Long-term Actions
1. Implement comprehensive security logging and monitoring
2. Add security testing to CI/CD pipeline
3. Conduct regular security audits
4. Implement dependency vulnerability scanning
5. Add security documentation and guidelines
6. Consider implementing Content Security Policy (CSP)

---

## OWASP Top 10 Compliance

| OWASP Top 10 Item | Status | Notes |
|-------------------|--------|-------|
| A01:2021 – Broken Access Control | ⚠️ Needs Improvement | IP-based auth, default auth issues |
| A02:2021 – Cryptographic Failures | ❌ Critical Issues | Weak password hashing |
| A03:2021 – Injection | ❌ Critical Issues | Command injection, code injection |
| A04:2021 – Insecure Design | ⚠️ Needs Improvement | Multiple design issues |
| A05:2021 – Security Misconfiguration | ⚠️ Needs Improvement | CORS, environment exposure |
| A06:2021 – Vulnerable Components | ✅ Good | Dependencies appear managed |
| A07:2021 – Authentication Failures | ⚠️ Needs Improvement | Weak hashing, no rate limiting |
| A08:2021 – Software and Data Integrity | ⚠️ Needs Improvement | No SBOM, limited integrity checks |
| A09:2021 – Security Logging Failures | ⚠️ Needs Improvement | Limited security logging |
| A10:2021 – Server-Side Request Forgery | ✅ Not Applicable | No obvious SSRF issues |

---

## Conclusion

The Scrypted codebase has several critical security vulnerabilities that require immediate attention, particularly around code injection, command injection, and weak authentication mechanisms. While the application demonstrates good architectural practices with plugin isolation and RPC security, significant improvements are needed in input validation, authentication, and secure coding practices.

**Overall Security Rating:** ⚠️ **NEEDS IMPROVEMENT**

**Priority Actions:**
1. Address all Critical and High severity findings
2. Implement comprehensive input validation
3. Strengthen authentication mechanisms
4. Add security testing to development workflow

---

*This security review is based on static code analysis and should be supplemented with dynamic security testing, penetration testing, and regular security audits.*

