# Justfile for Scrypted Development
# Install just: https://github.com/casey/just

# Default recipe - show available commands
default:
    @just --list

# Run all tests
test-all:
    #!/usr/bin/env bash
    @echo "Running all tests..."
    @cd common && npm test
    @cd ../server && npm test

# Run common package tests
test-common:
    @cd common && npm test

# Run server package tests
test-server:
    @cd server && npm test

# Run security tests
test-security:
    @cd common && npm test -- secure-eval.test.ts

# Run tests with coverage
test-coverage:
    #!/usr/bin/env bash
    @echo "Running tests with coverage..."
    @cd common && npm run test:coverage
    @cd ../server && npm run test:coverage

# Build all packages
build:
    #!/usr/bin/env bash
    @echo "Building all packages..."
    @cd common && npm run build
    @cd ../server && npm run build

# Install dependencies for all packages
install-all:
    #!/usr/bin/env bash
    @echo "Installing dependencies..."
    @npm install
    @cd common && npm install
    @cd ../server && npm install

# Run linting
lint:
    @echo "Running linters..."
    @cd common && npm run lint || echo "No lint script in common"
    @cd ../server && npm run lint || echo "No lint script in server"

# Clean build artifacts
clean:
    #!/usr/bin/env bash
    @echo "Cleaning build artifacts..."
    @cd common && rm -rf dist node_modules/.cache
    @cd ../server && rm -rf dist node_modules/.cache
    @rm -rf common/coverage server/coverage

# Security review
security-review:
    @echo "Security Review Documents:"
    @echo "- SECURITY_REVIEW.md"
    @echo "- SECURITY_IMPROVEMENT_PLAN.md"
    @echo "- SECURITY_IMPLEMENTATION_GUIDE.md"
    @echo "- PHASE_1_1_REVIEW.md"

# Show test results summary
test-summary:
    #!/usr/bin/env bash
    @echo "=== Test Summary ==="
    @cd common && npm test --silent 2>&1 | grep -E "(Test Suites|Tests:)" || true
    @cd ../server && npm test --silent 2>&1 | grep -E "(Test Suites|Tests:)" || true

# Watch mode for common tests
watch-common:
    @cd common && npm run test:watch

# Watch mode for server tests
watch-server:
    @cd server && npm run test:watch

# Run Phase 1.1 tests (security)
test-phase1-1:
    @cd common && npm test -- secure-eval.test.ts

# Setup development environment
setup:
    #!/usr/bin/env bash
    @echo "Setting up development environment..."
    @just install-all
    @just build
    @just test-all

# Quick check - build and test
check:
    #!/usr/bin/env bash
    @just build
    @just test-all

