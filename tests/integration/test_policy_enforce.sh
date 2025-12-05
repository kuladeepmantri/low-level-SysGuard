#!/bin/bash
# Integration test: Policy enforcement

set -e

AURIS="./auris"
DATA_DIR="/tmp/auris_test_$$"

cleanup() {
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"

echo "=== Test: Policy enforcement ==="

# First, learn the behavior
$AURIS learn -d "$DATA_DIR" -t baseline-trace -- /bin/true

# Build profile
$AURIS profile -d "$DATA_DIR" -t baseline-trace

# Get profile ID from the output directory
PROFILE_ID=$(ls "$DATA_DIR/profiles/" | head -1 | sed 's/.json$//')

if [ -z "$PROFILE_ID" ]; then
    echo "FAIL: No profile created"
    exit 1
fi

# Generate policy
$AURIS policy -d "$DATA_DIR" -p "$PROFILE_ID"

# Get policy ID
POLICY_ID=$(ls "$DATA_DIR/policies/" | head -1 | sed 's/.json$//')

if [ -z "$POLICY_ID" ]; then
    echo "FAIL: No policy created"
    exit 1
fi

# Enforce in alert mode
$AURIS enforce -d "$DATA_DIR" -P "$POLICY_ID" -m alert -- /bin/true

echo "PASS: Policy enforcement"
exit 0
