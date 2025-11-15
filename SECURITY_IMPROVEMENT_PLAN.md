# Security Improvement Plan

**Date:** 2024  
**Status:** Implementation Plan  
**Priority:** Critical Security Enhancements

---

## Overview

This document outlines a comprehensive plan to address the security vulnerabilities identified in the security review. The plan is organized into phases, with each phase building upon the previous one to systematically improve the security posture of the Scrypted application.

---

## Phase 1: Critical Security Fixes (Week 1-2)

### Priority: IMMEDIATE - Address Critical Vulnerabilities

#### 1.1 Eliminate Code Injection via eval()

**Objective:** Replace unsafe `eval()` usage with secure expression evaluation

**Tasks:**
- [ ] **Task 1.1.1:** Install safe expression evaluator library
  - Research and select: `expr-eval`, `mathjs`, or `safe-eval`
  - Add to `package.json`: `npm install expr-eval`
  - Document choice and rationale

- [ ] **Task 1.1.2:** Create secure expression evaluator wrapper
  - Create `common/src/secure-eval.ts`
  - Implement wrapper that:
    - Validates input syntax
    - Restricts available functions/operators
    - Implements timeout mechanism
    - Logs all evaluations for audit

- [ ] **Task 1.1.3:** Replace eval() in automation conditions
  - File: `plugins/core/src/automation.ts:575`
  - Replace `eval()` with secure evaluator
  - Add input validation (max length, allowed characters)
  - Add unit tests for edge cases

- [ ] **Task 1.1.4:** Update documentation
  - Document expression syntax limitations
  - Provide examples of valid expressions
  - Add security warnings for plugin developers

**Testing:**
- Unit tests for expression evaluator
- Integration tests for automation conditions
- Negative tests (malicious input attempts)
- Performance tests (timeout handling)

**Acceptance Criteria:**
- No `eval()` calls remain in automation code
- All expressions validated before execution
- Timeout mechanism prevents DoS
- Audit logging implemented

---

#### 1.2 Fix Command Injection in Shell Scripts

**Objective:** Secure shell script execution with proper sanitization

**Tasks:**
- [ ] **Task 1.2.1:** Design secure shell execution API
  - Define whitelist of allowed shell features
  - Design sandboxed execution environment
  - Plan command timeout mechanism
  - Plan resource limits (CPU, memory)

- [ ] **Task 1.2.2:** Implement secure shell executor
  - Create `common/src/secure-shell-executor.ts`
  - Implement:
    - Input sanitization (remove dangerous characters)
    - Command whitelist validation
    - Timeout enforcement
    - Resource limits
    - Output sanitization

- [ ] **Task 1.2.3:** Replace unsafe shell execution
  - File: `plugins/core/src/builtins/shellscript.ts:17-28`
  - Replace `spawn('sh', ...)` with secure executor
  - Add environment variable filtering
  - Implement output size limits

- [ ] **Task 1.2.4:** Add security controls
  - Require admin authentication for shell script execution
  - Add audit logging (who, what, when, result)
  - Implement rate limiting per user
  - Add warning UI for shell script usage

**Testing:**
- Unit tests for sanitization
- Integration tests for command execution
- Penetration tests (command injection attempts)
- Performance tests (timeout/resource limits)

**Acceptance Criteria:**
- No direct shell execution without sanitization
- All commands validated against whitelist
- Timeout and resource limits enforced
- Comprehensive audit logging

---

#### 1.3 Fix Path Traversal Vulnerabilities

**Objective:** Prevent directory traversal attacks in file operations

**Tasks:**
- [ ] **Task 1.3.1:** Create secure path utilities
  - Create `common/src/secure-path.ts`
  - Implement:
    - `normalizePath()` - resolves and normalizes paths
    - `validatePath()` - ensures path stays within allowed directory
    - `sanitizePath()` - removes dangerous characters
    - `resolveSafePath()` - combines all checks

- [ ] **Task 1.3.2:** Fix sendFile() method
  - File: `server/src/http-interfaces.ts:45-70`
  - Replace path handling with secure utilities
  - Remove fallback to absolute paths
  - Add path validation before file access
  - Implement allowed directory whitelist

- [ ] **Task 1.3.3:** Fix RTSP file operations
  - File: `plugins/prebuffer-mixin/src/file-rtsp-server.ts:36-90`
  - Validate file paths from headers
  - Restrict to specific recording directory
  - Add path normalization

- [ ] **Task 1.3.4:** Audit all file operations
  - Search codebase for file system operations
  - Apply secure path utilities to all file operations
  - Add unit tests for path validation

**Testing:**
- Unit tests for path normalization
- Integration tests for file access
- Penetration tests (path traversal attempts)
- Edge case tests (symlinks, special characters)

**Acceptance Criteria:**
- All file paths validated before access
- No directory traversal possible
- Paths restricted to intended directories
- Comprehensive test coverage

---

#### 1.4 Strengthen Password Hashing

**Objective:** Replace weak SHA-256 with proper key derivation

**Tasks:**
- [ ] **Task 1.4.1:** Install password hashing library
  - Option 1: Use Node.js built-in `crypto.pbkdf2()`
  - Option 2: Install `bcrypt` or `argon2`
  - Decision: Use `crypto.pbkdf2()` (no external dependency)
  - Document choice

- [ ] **Task 1.4.2:** Create password hashing utility
  - Create `server/src/services/password-hash.ts`
  - Implement:
    - `hashPassword()` - PBKDF2 with 100,000+ iterations
    - `verifyPassword()` - constant-time comparison
    - `needsRehash()` - check if password needs upgrade
    - Migration helper for existing passwords

- [ ] **Task 1.4.3:** Update password storage
  - File: `server/src/services/users.ts:81-86`
  - Replace SHA-256 with PBKDF2
  - Add password hash version field
  - Implement password upgrade on login

- [ ] **Task 1.4.4:** Add password policy
  - Minimum password length (12+ characters)
  - Password complexity requirements
  - Password expiration (optional)
  - Password history (prevent reuse)

**Testing:**
- Unit tests for password hashing
- Performance tests (hashing speed)
- Integration tests (login flow)
- Migration tests (old password compatibility)

**Acceptance Criteria:**
- PBKDF2 with 100,000+ iterations
- Constant-time password comparison
- Password upgrade mechanism
- Password policy enforced

---

#### 1.5 Remove Token from Query Parameters

**Objective:** Eliminate token exposure in URLs

**Tasks:**
- [ ] **Task 1.5.1:** Remove query parameter token support
  - File: `server/src/scrypted-server-main.ts:334-336`
  - Remove `req.query['scryptedToken']` handling
  - Add deprecation warning in logs
  - Document migration path

- [ ] **Task 1.5.2:** Enforce Authorization header only
  - Update authentication middleware
  - Add validation for Authorization header format
  - Return clear error messages for deprecated methods

- [ ] **Task 1.5.3:** Update client code
  - Search for query parameter token usage
  - Update to use Authorization headers
  - Update API documentation

- [ ] **Task 1.5.4:** Add token rotation mechanism
  - Implement token refresh endpoint
  - Add token expiration
  - Add token revocation capability

**Testing:**
- Unit tests for authentication
- Integration tests (token flow)
- Negative tests (query parameter rejection)
- Migration tests (backward compatibility)

**Acceptance Criteria:**
- No token support in query parameters
- All tokens use Authorization header
- Token rotation implemented
- Clear migration documentation

---

## Phase 2: High-Priority Security Enhancements (Week 3-4)

### Priority: HIGH - Strengthen Authentication and Input Validation

#### 2.1 Implement Rate Limiting

**Objective:** Prevent brute-force and DoS attacks

**Tasks:**
- [ ] **Task 2.1.1:** Install rate limiting library
  - Install `express-rate-limit` or `rate-limiter-flexible`
  - Add to `server/package.json`

- [ ] **Task 2.1.2:** Create rate limiting middleware
  - Create `server/src/middleware/rate-limit.ts`
  - Implement:
    - Login endpoint rate limiting (5 attempts per 15 minutes)
    - Token validation rate limiting
    - General API rate limiting
    - IP-based and user-based limits

- [ ] **Task 2.1.3:** Add account lockout
  - Lock account after 5 failed login attempts
  - Implement exponential backoff
  - Add unlock mechanism (admin or time-based)
  - Log all lockout events

- [ ] **Task 2.1.4:** Add CAPTCHA for repeated failures
  - Integrate CAPTCHA service (optional)
  - Trigger after 3 failed attempts
  - Add UI for CAPTCHA display

**Testing:**
- Unit tests for rate limiting
- Integration tests (rate limit enforcement)
- Load tests (rate limit performance)
- Edge case tests (concurrent requests)

**Acceptance Criteria:**
- Rate limiting on all authentication endpoints
- Account lockout after failed attempts
- Configurable rate limits
- Comprehensive logging

---

#### 2.2 Strengthen Input Validation

**Objective:** Validate and sanitize all user inputs

**Tasks:**
- [ ] **Task 2.2.1:** Install validation library
  - Install `joi` or `zod` for schema validation
  - Add to `server/package.json`

- [ ] **Task 2.2.2:** Create validation middleware
  - Create `server/src/middleware/validation.ts`
  - Implement:
    - Request body validation
    - Query parameter validation
    - Path parameter validation
    - Header validation

- [ ] **Task 2.2.3:** Add JSON parsing limits
  - File: `server/src/scrypted-server-main.ts`
  - Configure `body-parser` with size limits
  - Add JSON depth limits
  - Add timeout for parsing

- [ ] **Task 2.2.4:** Validate plugin inputs
  - File: `plugins/google-home/src/main.ts:616`
  - File: `plugins/alexa/src/main.ts:647`
  - Add schema validation for request bodies
  - Add size limits
  - Add error handling

**Testing:**
- Unit tests for validation
- Integration tests (request validation)
- Negative tests (malicious inputs)
- Performance tests (large payloads)

**Acceptance Criteria:**
- All inputs validated
- Request size limits enforced
- Clear validation error messages
- Comprehensive test coverage

---

#### 2.3 Secure CORS Configuration

**Objective:** Prevent CORS misconfiguration attacks

**Tasks:**
- [ ] **Task 2.3.1:** Implement CORS validation
  - File: `server/src/runtime.ts:199-218`
  - Add origin format validation
  - Implement origin whitelist
  - Add origin validation on add

- [ ] **Task 2.3.2:** Restrict plugin CORS modification
  - Require admin authentication for CORS changes
  - Add validation for plugin-originated CORS
  - Log all CORS modifications

- [ ] **Task 2.3.3:** Implement CORS policy
  - Default deny policy
  - Explicit allow list
  - Wildcard restrictions
  - Document CORS configuration

- [ ] **Task 2.3.4:** Add CORS security headers
  - Implement proper CORS headers
  - Add Vary header
  - Configure credentials handling

**Testing:**
- Unit tests for CORS validation
- Integration tests (CORS headers)
- Security tests (CORS bypass attempts)
- Configuration tests

**Acceptance Criteria:**
- CORS origins validated
- Plugin CORS restricted
- Secure default policy
- Comprehensive logging

---

#### 2.4 Implement Secure Error Handling

**Objective:** Prevent information disclosure through errors

**Tasks:**
- [ ] **Task 2.4.1:** Create error handling middleware
  - Create `server/src/middleware/error-handler.ts`
  - Implement:
    - Error sanitization
    - Error logging (server-side)
    - Generic error responses (client-side)
    - Error code mapping

- [ ] **Task 2.4.2:** Replace direct error responses
  - File: `server/src/plugin/plugin-http.ts:126-129`
  - File: `plugins/google-home/src/main.ts:608`
  - Replace with error handler
  - Add error codes
  - Sanitize error messages

- [ ] **Task 2.4.3:** Implement error logging
  - Log detailed errors server-side
  - Include stack traces (dev only)
  - Add error correlation IDs
  - Implement error alerting

- [ ] **Task 2.4.4:** Add error response standardization
  - Standard error response format
  - Error code system
  - User-friendly error messages
  - Error documentation

**Testing:**
- Unit tests for error handling
- Integration tests (error responses)
- Security tests (information disclosure)
- Logging tests

**Acceptance Criteria:**
- No sensitive information in error responses
- Comprehensive error logging
- Standardized error format
- Error correlation IDs

---

## Phase 3: Medium-Priority Security Improvements (Week 5-6)

### Priority: MEDIUM - Enhance Security Posture

#### 3.1 Secure Environment Variable Exposure

**Objective:** Prevent sensitive configuration exposure

**Tasks:**
- [ ] **Task 3.1.1:** Create environment variable filter
  - File: `server/src/services/info.ts:10-12`
  - Implement whitelist of safe variables
  - Filter sensitive variables
  - Add variable masking

- [ ] **Task 3.1.2:** Restrict info endpoint access
  - Require authentication
  - Add admin-only access
  - Implement rate limiting
  - Add access logging

- [ ] **Task 3.1.3:** Document environment variables
  - List all environment variables
  - Mark sensitive variables
  - Document usage
  - Add security warnings

**Testing:**
- Unit tests for filtering
- Integration tests (endpoint access)
- Security tests (information disclosure)
- Documentation review

**Acceptance Criteria:**
- Sensitive variables filtered
- Endpoint access restricted
- Comprehensive documentation
- Security warnings added

---

#### 3.2 Implement HTTPS Enforcement

**Objective:** Enforce secure connections

**Tasks:**
- [ ] **Task 3.2.1:** Add HSTS headers
  - Implement HSTS middleware
  - Configure HSTS policy
  - Add preload support (optional)
  - Document HSTS configuration

- [ ] **Task 3.2.2:** Implement HTTPS redirect
  - Redirect HTTP to HTTPS
  - Exclude health check endpoints
  - Add configuration option
  - Document exceptions

- [ ] **Task 3.2.3:** Secure cookie configuration
  - Set Secure flag on cookies
  - Set HttpOnly flag
  - Set SameSite attribute
  - Configure cookie expiration

- [ ] **Task 3.2.4:** Add security headers
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection

**Testing:**
- Unit tests for headers
- Integration tests (HTTPS redirect)
- Security tests (header validation)
- Configuration tests

**Acceptance Criteria:**
- HSTS headers implemented
- HTTP to HTTPS redirect
- Secure cookie configuration
- Security headers added

---

#### 3.3 Strengthen Token Security

**Objective:** Improve token generation and validation

**Tasks:**
- [ ] **Task 3.3.1:** Implement constant-time comparison
  - File: `server/src/scrypted-server-main.ts:273-311`
  - Replace string comparison with `crypto.timingSafeEqual()`
  - Add timing attack tests
  - Document security improvement

- [ ] **Task 3.3.2:** Add token expiration
  - Implement token expiration
  - Add refresh token mechanism
  - Add token revocation
  - Update token validation

- [ ] **Task 3.3.3:** Improve token generation
  - Use `crypto.randomBytes()` (already done)
  - Increase token length if needed
  - Add token entropy validation
  - Document token format

- [ ] **Task 3.3.4:** Add token rotation
  - Implement token refresh endpoint
  - Add token rotation policy
  - Implement token blacklist
  - Add token audit logging

**Testing:**
- Unit tests for token validation
- Security tests (timing attacks)
- Integration tests (token flow)
- Performance tests

**Acceptance Criteria:**
- Constant-time token comparison
- Token expiration implemented
- Token rotation mechanism
- Comprehensive audit logging

---

#### 3.4 Secure File Operations

**Objective:** Validate all file operations

**Tasks:**
- [ ] **Task 3.4.1:** Apply secure path utilities
  - Use utilities from Phase 1.3
  - Apply to all file operations
  - Add file operation logging
  - Implement file access audit

- [ ] **Task 3.4.2:** Restrict file operations
  - Implement file operation permissions
  - Add admin-only file operations
  - Restrict file types
  - Add file size limits

- [ ] **Task 3.4.3:** Add file operation monitoring
  - Log all file operations
  - Monitor suspicious patterns
  - Add alerts for anomalies
  - Implement file access reports

**Testing:**
- Unit tests for file operations
- Integration tests (file access)
- Security tests (unauthorized access)
- Audit tests

**Acceptance Criteria:**
- All file operations validated
- File access restricted
- Comprehensive audit logging
- Monitoring implemented

---

## Phase 4: Security Infrastructure (Week 7-8)

### Priority: MEDIUM - Build Security Foundation

#### 4.1 Implement Security Logging

**Objective:** Comprehensive security event logging

**Tasks:**
- [ ] **Task 4.1.1:** Design security event schema
  - Define security event types
  - Design event structure
  - Plan event storage
  - Plan event retention

- [ ] **Task 4.1.2:** Implement security logger
  - Create `server/src/services/security-logger.ts`
  - Implement:
    - Authentication events
    - Authorization failures
    - Security violations
    - Suspicious activities

- [ ] **Task 4.1.3:** Add security event logging
  - Log all authentication attempts
  - Log authorization failures
  - Log security violations
  - Log file operations

- [ ] **Task 4.1.4:** Implement log analysis
  - Add log aggregation
  - Implement alerting
  - Add security dashboards
  - Plan incident response

**Testing:**
- Unit tests for logging
- Integration tests (log collection)
- Performance tests (log volume)
- Alert tests

**Acceptance Criteria:**
- Comprehensive security logging
- Log aggregation implemented
- Alerting configured
- Incident response plan

---

#### 4.2 Add Security Testing

**Objective:** Integrate security testing into CI/CD

**Tasks:**
- [ ] **Task 4.2.1:** Add dependency scanning
  - Integrate `npm audit` or Snyk
  - Add to CI pipeline
  - Configure alerting
  - Document process

- [ ] **Task 4.2.2:** Add SAST scanning
  - Integrate ESLint security plugin
  - Add SonarQube or similar
  - Configure rules
  - Add to CI pipeline

- [ ] **Task 4.2.3:** Add security unit tests
  - Create security test suite
  - Add penetration test cases
  - Add fuzzing tests
  - Integrate into test suite

- [ ] **Task 4.2.4:** Add security documentation
  - Document security testing process
  - Add security test guidelines
  - Document security requirements
  - Add security checklist

**Testing:**
- CI pipeline tests
- Security scan validation
- Test coverage validation
- Documentation review

**Acceptance Criteria:**
- Dependency scanning in CI
- SAST scanning configured
- Security test suite
- Comprehensive documentation

---

#### 4.3 Implement SBOM Generation

**Objective:** Generate Software Bill of Materials

**Tasks:**
- [ ] **Task 4.3.1:** Choose SBOM format
  - Select SPDX or CycloneDX
  - Document choice
  - Plan SBOM storage
  - Plan SBOM distribution

- [ ] **Task 4.3.2:** Implement SBOM generation
  - Integrate SBOM generator
  - Add to build process
  - Configure SBOM format
  - Add SBOM validation

- [ ] **Task 4.3.3:** Add SBOM to CI/CD
  - Generate SBOM on build
  - Store SBOM artifacts
  - Add SBOM signing
  - Distribute SBOM

- [ ] **Task 4.3.4:** Integrate SBOM with security
  - Link SBOM to vulnerability scans
  - Add SBOM to security reports
  - Implement SBOM tracking
  - Document SBOM process

**Testing:**
- SBOM generation tests
- SBOM validation tests
- CI integration tests
- Documentation review

**Acceptance Criteria:**
- SBOM generated on build
- SBOM stored and signed
- SBOM integrated with security
- Comprehensive documentation

---

#### 4.4 Add Security Documentation

**Objective:** Comprehensive security documentation

**Tasks:**
- [ ] **Task 4.4.1:** Create security guide
  - Document security architecture
  - Document security controls
  - Document threat model
  - Document security processes

- [ ] **Task 4.4.2:** Add developer security guide
  - Secure coding guidelines
  - Security testing guidelines
  - Security review process
  - Security incident response

- [ ] **Task 4.4.3:** Add user security guide
  - Security best practices
  - Configuration security
  - Security recommendations
  - Incident reporting

- [ ] **Task 4.4.4:** Maintain security documentation
  - Regular documentation updates
  - Version control for docs
  - Documentation review process
  - Documentation testing

**Testing:**
- Documentation review
- Documentation testing
- User feedback
- Regular updates

**Acceptance Criteria:**
- Comprehensive security documentation
- Developer guidelines
- User security guide
- Regular documentation updates

---

## Implementation Guidelines

### Development Process

1. **Test-Driven Development (TDD)**
   - Write security tests before implementation
   - Use BDD-style test names
   - Tests should serve as security specifications
   - Each test should verify one security control

2. **Code Review**
   - Security-focused code reviews
   - Check for security anti-patterns
   - Verify security test coverage
   - Review security documentation

3. **Security Testing**
   - Unit tests for security controls
   - Integration tests for security flows
   - Penetration tests for vulnerabilities
   - Regular security audits

### Security Principles

1. **Defense in Depth**
   - Multiple layers of security
   - Fail-secure defaults
   - Principle of least privilege
   - Defense against multiple attack vectors

2. **Secure by Default**
   - Secure default configurations
   - Require explicit opt-in for risky features
   - Clear security warnings
   - Secure out-of-the-box experience

3. **Security Monitoring**
   - Comprehensive logging
   - Security event monitoring
   - Anomaly detection
   - Incident response

### Success Metrics

- **Security Test Coverage:** >90% for security-critical code
- **Vulnerability Reduction:** 100% of critical vulnerabilities addressed
- **Security Incident Response:** <1 hour detection time
- **Security Documentation:** Complete and up-to-date

---

## Risk Assessment

### High Risk (Address Immediately)
- Code injection vulnerabilities
- Command injection vulnerabilities
- Path traversal vulnerabilities
- Weak authentication mechanisms

### Medium Risk (Address Soon)
- Input validation gaps
- CORS misconfiguration
- Error information disclosure
- Missing rate limiting

### Low Risk (Address When Possible)
- Security documentation gaps
- Security testing gaps
- Security monitoring gaps
- SBOM generation

---

## Timeline Summary

| Phase | Duration | Priority | Key Deliverables |
|-------|----------|----------|-----------------|
| Phase 1 | Week 1-2 | CRITICAL | Code injection fixes, command injection fixes, path traversal fixes, password hashing, token security |
| Phase 2 | Week 3-4 | HIGH | Rate limiting, input validation, CORS security, error handling |
| Phase 3 | Week 5-6 | MEDIUM | Environment variable security, HTTPS enforcement, token security, file operations |
| Phase 4 | Week 7-8 | MEDIUM | Security logging, security testing, SBOM generation, security documentation |

---

## Dependencies

### External Dependencies
- `expr-eval` or `mathjs` - Safe expression evaluation
- `express-rate-limit` - Rate limiting
- `joi` or `zod` - Input validation
- Security scanning tools (Snyk, SonarQube, etc.)
- SBOM generation tools

### Internal Dependencies
- Test infrastructure
- CI/CD pipeline
- Logging infrastructure
- Documentation system

---

## Rollout Strategy

1. **Phase 1:** Critical fixes deployed immediately
2. **Phase 2:** High-priority enhancements deployed incrementally
3. **Phase 3:** Medium-priority improvements deployed gradually
4. **Phase 4:** Security infrastructure built continuously

### Deployment Considerations
- Backward compatibility for API changes
- Migration paths for breaking changes
- Feature flags for gradual rollout
- Rollback plans for each phase

---

## Monitoring and Maintenance

### Ongoing Tasks
- Regular security audits (quarterly)
- Dependency vulnerability scanning (weekly)
- Security log review (daily)
- Security documentation updates (as needed)

### Success Indicators
- Zero critical vulnerabilities
- <5 high-priority vulnerabilities
- 100% security test coverage for critical paths
- <1 hour security incident response time

---

## Conclusion

This security improvement plan provides a structured approach to addressing all identified security vulnerabilities. By following this plan, the Scrypted application will achieve a significantly improved security posture, addressing critical vulnerabilities first and then building a comprehensive security foundation.

**Next Steps:**
1. Review and approve this plan
2. Assign resources to Phase 1 tasks
3. Begin implementation of critical fixes
4. Schedule regular progress reviews

---

*This plan should be reviewed and updated regularly as new security requirements emerge or as the threat landscape evolves.*

