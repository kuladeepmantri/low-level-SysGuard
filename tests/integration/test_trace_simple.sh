#!/bin/bash
# Integration test: Simple trace capture

set -e

AURIS="./auris"
DATA_DIR="/tmp/auris_test_$$"

cleanup() {
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

# Create test directory
mkdir -p "$DATA_DIR"

echo "=== Test: Simple trace capture ==="

# Trace /bin/true
$AURIS learn -d "$DATA_DIR" -t test-trace-1 -- /bin/true

# Verify trace was created
if [ ! -f "$DATA_DIR/traces/test-trace-1.json" ]; then
    echo "FAIL: Trace file not created"
    exit 1
fi

# Verify trace contains expected fields
if ! grep -q '"binary_path"' "$DATA_DIR/traces/test-trace-1.json"; then
    echo "FAIL: Trace missing binary_path"
    exit 1
fi

if ! grep -q '"events"' "$DATA_DIR/traces/test-trace-1.json"; then
    echo "FAIL: Trace missing events"
    exit 1
fi

echo "PASS: Simple trace capture"
exit 0
