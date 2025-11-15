#!/bin/bash
# Run all tests across all packages

set -e

echo "=========================================="
echo "Running All Tests"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0

# Function to run tests in a package
run_package_tests() {
    local package=$1
    local package_name=$2
    
    echo -e "${BLUE}Testing ${package_name}...${NC}"
    cd "$package"
    
    if [ -f "package.json" ] && grep -q '"test"' package.json; then
        if npm test 2>&1 | tee /tmp/test-output.log; then
            # Extract test counts using portable grep
            local passed=$(grep -oE '[0-9]+ passed' /tmp/test-output.log | grep -oE '[0-9]+' | head -1 || echo "0")
            local failed=$(grep -oE '[0-9]+ failed' /tmp/test-output.log | grep -oE '[0-9]+' | head -1 || echo "0")
            local total=$(grep -oE '[0-9]+ total' /tmp/test-output.log | grep -oE '[0-9]+' | head -1 || echo "0")
            
            # Convert to integers, defaulting to 0 if empty
            passed=${passed:-0}
            failed=${failed:-0}
            total=${total:-0}
            
            TOTAL_TESTS=$((TOTAL_TESTS + total))
            TOTAL_PASSED=$((TOTAL_PASSED + passed))
            TOTAL_FAILED=$((TOTAL_FAILED + failed))
            
            if [ "$failed" -eq 0 ] && [ "$passed" -gt 0 ]; then
                echo -e "${GREEN}✅ ${package_name}: ${passed} tests passed${NC}"
            elif [ "$failed" -gt 0 ]; then
                echo -e "❌ ${package_name}: ${failed} tests failed"
            else
                echo -e "⚠️  ${package_name}: Tests completed"
            fi
        else
            echo -e "❌ ${package_name}: Tests failed"
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    else
        echo -e "⚠️  ${package_name}: No test script found"
    fi
    
    cd ..
    echo ""
}

# Run tests for each package
run_package_tests "common" "Common Package"
run_package_tests "server" "Server Package"

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total Tests: ${TOTAL_TESTS}"
echo -e "${GREEN}Passed: ${TOTAL_PASSED}${NC}"
if [ "$TOTAL_FAILED" -gt 0 ]; then
    echo -e "Failed: ${TOTAL_FAILED}"
    exit 1
else
    echo -e "${GREEN}Failed: 0${NC}"
    echo ""
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
fi

