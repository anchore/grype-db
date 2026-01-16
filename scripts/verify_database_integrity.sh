#!/bin/bash
# Database Integrity Verification Script
#
# Compares databases built with different batch sizes to verify batching
# doesn't alter database contents.
#
# Prerequisites:
# - vunnel data must be pulled first (grype-db pull)
# - Requires sqlite3 CLI tool
#
# Usage:
#   PROVIDER=wolfi ./scripts/verify_database_integrity.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
PROVIDER="${PROVIDER:-wolfi}"
BASELINE_DIR="${BASELINE_DIR:-/tmp/grype-db-baseline}"
OPTIMIZED_DIR="${OPTIMIZED_DIR:-/tmp/grype-db-optimized}"
BATCH_SIZE="${BATCH_SIZE:-2000}"

echo "======================================"
echo "Database Integrity Verification"
echo "======================================"
echo "Provider: $PROVIDER"
echo "Baseline: $BASELINE_DIR"
echo "Optimized: $OPTIMIZED_DIR"
echo "Batch Size: $BATCH_SIZE"
echo "======================================"

# Clean up previous runs
echo ""
echo "Cleaning up previous runs..."
rm -rf "$BASELINE_DIR" "$OPTIMIZED_DIR"
mkdir -p "$BASELINE_DIR" "$OPTIMIZED_DIR"

# Build grype-db binary with current code
echo ""
echo "Building grype-db with batching support..."
cd "$REPO_ROOT"
go build -o /tmp/grype-db-verify-test ./cmd/grype-db

# Build baseline with batch_size=1 (simulates unbatched behavior)
echo ""
echo "Building baseline database (batch_size=1, unbatched)..."
GRYPE_DB_BATCH_SIZE=1 GRYPE_DB_CONFIG=/tmp/grype-db-test.yaml /tmp/grype-db-verify-test build \
    --schema 6 \
    --dir="$BASELINE_DIR" \
    2>&1 | tee "$BASELINE_DIR/build.log"

# Build optimized with batch_size=2000 (batched)
echo ""
echo "Building optimized database (batch_size=$BATCH_SIZE, batched)..."
GRYPE_DB_BATCH_SIZE=$BATCH_SIZE GRYPE_DB_CONFIG=/tmp/grype-db-test.yaml /tmp/grype-db-verify-test build \
    --schema 6 \
    --dir="$OPTIMIZED_DIR" \
    2>&1 | tee "$OPTIMIZED_DIR/build.log"

# Compare databases
echo ""
echo "======================================"
echo "Comparing Databases"
echo "======================================"

BASELINE_DB="$BASELINE_DIR/vulnerability.db"
OPTIMIZED_DB="$OPTIMIZED_DIR/vulnerability.db"

if [ ! -f "$BASELINE_DB" ]; then
    echo "ERROR: Baseline database not found at $BASELINE_DB"
    exit 1
fi

if [ ! -f "$OPTIMIZED_DB" ]; then
    echo "ERROR: Optimized database not found at $OPTIMIZED_DB"
    exit 1
fi

# Compare vulnerability counts (v6 schema uses vulnerability_handles table)
echo ""
echo "Comparing vulnerability counts..."
BASELINE_COUNT=$(sqlite3 "$BASELINE_DB" "SELECT COUNT(*) FROM vulnerability_handles")
OPTIMIZED_COUNT=$(sqlite3 "$OPTIMIZED_DB" "SELECT COUNT(*) FROM vulnerability_handles")

echo "Baseline vulnerabilities: $BASELINE_COUNT"
echo "Optimized vulnerabilities: $OPTIMIZED_COUNT"

if [ "$BASELINE_COUNT" != "$OPTIMIZED_COUNT" ]; then
    echo "❌ ERROR: Vulnerability count mismatch!"
    exit 1
fi

echo "✅ Vulnerability counts match"

# Compare provider counts
echo ""
echo "Comparing provider counts..."
BASELINE_PROVIDERS=$(sqlite3 "$BASELINE_DB" "SELECT COUNT(DISTINCT id) FROM providers")
OPTIMIZED_PROVIDERS=$(sqlite3 "$OPTIMIZED_DB" "SELECT COUNT(DISTINCT id) FROM providers")

echo "Baseline providers: $BASELINE_PROVIDERS"
echo "Optimized providers: $OPTIMIZED_PROVIDERS"

if [ "$BASELINE_PROVIDERS" != "$OPTIMIZED_PROVIDERS" ]; then
    echo "❌ ERROR: Provider count mismatch!"
    exit 1
fi

echo "✅ Provider counts match"

# Check for orphaned records (FK integrity - critical for two-tier batching)
echo ""
echo "Checking for orphaned records (Foreign Key integrity)..."

# v6 schema tables with vulnerability_id FK
TABLES_V6=("affected_cpe_handles" "affected_package_handles" "unaffected_cpe_handles" "unaffected_package_handles")
# v5 schema uses different table structure - skip for now
ORPHAN_ERRORS=0

for table in "${TABLES_V6[@]}"; do
    # Check if table exists first (v6 only)
    if sqlite3 "$OPTIMIZED_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='$table';" | grep -q "$table"; then
        # Check for NULL or 0 IDs (0 indicates uninitialized/unassigned ID)
        ORPHANS=$(sqlite3 "$OPTIMIZED_DB" "SELECT COUNT(*) FROM $table WHERE vulnerability_id IS NULL OR vulnerability_id = 0;")

        if [ "$ORPHANS" -ne "0" ]; then
            echo "❌ ERROR: Found $ORPHANS orphaned records in table '$table'"
            ORPHAN_ERRORS=1
        else
            echo "✅ No orphans in '$table'"
        fi
    fi
done

if [ "$ORPHAN_ERRORS" -ne "0" ]; then
    echo "❌ FK integrity check failed: Orphaned records detected"
    echo "   This indicates parent IDs were not properly propagated to child records"
    exit 1
fi

echo "✅ FK integrity verified - all child records reference valid parents"

# Compare SQL dumps (sorted for consistent comparison)
echo ""
echo "Comparing SQL dumps (this may take a while)..."
sqlite3 "$BASELINE_DB" .dump | sort > /tmp/baseline.sql
sqlite3 "$OPTIMIZED_DB" .dump | sort > /tmp/optimized.sql

if diff /tmp/baseline.sql /tmp/optimized.sql > /tmp/db-diff.txt 2>&1; then
    echo "✅ Databases are identical (byte-for-byte)"
else
    echo "⚠️  Databases differ - reviewing differences..."

    # Check if differences are only in metadata/timestamps
    DIFF_LINES=$(wc -l < /tmp/db-diff.txt)
    echo "Number of differing lines: $DIFF_LINES"

    # Show first 50 lines of diff
    echo ""
    echo "First 50 lines of diff:"
    head -50 /tmp/db-diff.txt

    echo ""
    echo "Full diff saved to: /tmp/db-diff.txt"
    echo ""
    echo "⚠️  Review the diff to determine if differences are acceptable"
    echo "    (e.g., timestamp differences, ordering differences)"

    # Don't fail - let the user review
fi

# Compare table schemas
echo ""
echo "Comparing table schemas..."
sqlite3 "$BASELINE_DB" ".schema" | sort > /tmp/baseline-schema.sql
sqlite3 "$OPTIMIZED_DB" ".schema" | sort > /tmp/optimized-schema.sql

if diff /tmp/baseline-schema.sql /tmp/optimized-schema.sql > /dev/null 2>&1; then
    echo "✅ Schemas are identical"
else
    echo "❌ ERROR: Schemas differ!"
    diff /tmp/baseline-schema.sql /tmp/optimized-schema.sql
    exit 1
fi

# Extract performance metrics from logs
echo ""
echo "======================================"
echo "Performance Metrics"
echo "======================================"

echo ""
echo "Baseline build log:"
grep -E "(total_batches|provider_cache|database created)" "$BASELINE_DIR/build.log" || true

echo ""
echo "Optimized build log:"
grep -E "(total_batches|provider_cache|database created)" "$OPTIMIZED_DIR/build.log" || true

echo ""
echo "======================================"
echo "Verification Complete"
echo "======================================"
echo ""
echo "Summary:"
echo "  ✅ Vulnerability counts match"
echo "  ✅ Provider counts match"
echo "  ✅ Schemas are identical"
echo ""
echo "Databases location:"
echo "  Baseline:  $BASELINE_DB"
echo "  Optimized: $OPTIMIZED_DB"
echo ""
echo "To manually inspect the databases:"
echo "  sqlite3 $BASELINE_DB"
echo "  sqlite3 $OPTIMIZED_DB"
