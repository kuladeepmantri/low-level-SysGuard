#!/bin/bash
# Integration test: Profile comparison

set -e

AURIS="./auris"
DATA_DIR="/tmp/auris_test_$$"

cleanup() {
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"

echo "=== Test: Profile comparison ==="

# Learn baseline behavior
$AURIS learn -d "$DATA_DIR" -t baseline-trace -- /bin/true

# Build profile
$AURIS profile -d "$DATA_DIR" -t baseline-trace

# Get profile ID
PROFILE_ID=$(ls "$DATA_DIR/profiles/" | head -1 | sed 's/.json$//')

if [ -z "$PROFILE_ID" ]; then
    echo "FAIL: No profile created"
    exit 1
fi

# Compare same program (should have low deviation)
OUTPUT=$($AURIS compare -d "$DATA_DIR" -p "$PROFILE_ID" -j -- /bin/true)

if ! echo "$OUTPUT" | grep -q '"is_anomalous"'; then
    echo "FAIL: Comparison output missing is_anomalous field"
    exit 1
fi

echo "PASS: Profile comparison"
exit 0
