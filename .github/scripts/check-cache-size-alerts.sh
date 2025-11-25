#!/usr/bin/env bash
set -euo pipefail

# Check for size warning logs in the output and send alerts if needed
# This script is meant to be run after cache restore operations

LOG_FILE="${1:-}"

if [ -z "$LOG_FILE" ]; then
    echo "Usage: $0 <log-file>"
    exit 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

# Check for ERROR level size warnings (>=90%)
if grep -q "file size is dangerously close to extraction limit" "$LOG_FILE"; then
    echo "::error::Cache files are approaching size limits (>=90%)"
    echo "CACHE_SIZE_ALERT=critical" >> "$GITHUB_ENV"
    grep "file size is dangerously close to extraction limit" "$LOG_FILE" || true
    exit 0
fi

# Check for WARN level size warnings (>=80%)
if grep -q "file size is approaching extraction limit" "$LOG_FILE"; then
    echo "::warning::Cache files are approaching size limits (>=80%)"
    echo "CACHE_SIZE_ALERT=warning" >> "$GITHUB_ENV"
    grep "file size is approaching extraction limit" "$LOG_FILE" || true
    exit 0
fi

# Check for INFO level (>=50%)
if grep -q "large file extracted" "$LOG_FILE"; then
    echo "::notice::Large cache files detected (>=50% of limit)"
    grep "large file extracted" "$LOG_FILE" || true
fi

echo "No cache size alerts detected"
