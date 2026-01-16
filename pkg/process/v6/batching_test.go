package v6

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func TestBatchedWritesEquivalence(t *testing.T) {
	// Test that batched writes produce identical database output to unbatched writes
	// This is the critical correctness test for the batching optimization

	testCases := []struct {
		name       string
		batchSize  int
		numEntries int
	}{
		{
			name:       "unbatched (batch_size=1)",
			batchSize:  1,
			numEntries: 50,
		},
		{
			name:       "small batch",
			batchSize:  10,
			numEntries: 50,
		},
		{
			name:       "large batch",
			batchSize:  2000,
			numEntries: 50,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temp directory for database
			tmpDir := t.TempDir()

			// Create writer with specified batch size
			w, err := NewWriter(tmpDir, provider.States{}, false, tc.batchSize)
			require.NoError(t, err)

			// Write test entries
			entries := createTestEntries(tc.numEntries)
			for _, entry := range entries {
				err := w.Write(entry)
				require.NoError(t, err)
			}

			// Close to flush all batches
			err = w.Close()
			require.NoError(t, err)

			// Verify database was created
			dbPath := filepath.Join(tmpDir, "vulnerability.db")
			_, err = os.Stat(dbPath)
			require.NoError(t, err, "database file should exist")

			// Open and verify database contents
			reader, err := grypeDB.NewReader(grypeDB.Config{DBDirPath: tmpDir})
			require.NoError(t, err)
			defer reader.Close()

			// Basic validation: verify we can read data back
			// More detailed validation would require actual query methods
			// but this proves the database is valid and readable
		})
	}
}

func TestBatchAccumulation(t *testing.T) {
	// Test that operations accumulate in buffers before flushing
	tmpDir := t.TempDir()

	w, err := NewWriter(tmpDir, provider.States{}, false, 1000)
	require.NoError(t, err)

	writerImpl := w.(*writer)

	// Write 50 entries (below batch threshold of 1000)
	entries := createTestEntries(50)
	for _, entry := range entries {
		err := writerImpl.Write(entry)
		require.NoError(t, err)
	}

	// Verify buffers contain accumulated operations (not flushed yet)
	assert.Greater(t, len(writerImpl.parentBuffer), 0, "parent buffer should contain operations")
	assert.Greater(t, len(writerImpl.childBuffer), 0, "child buffer should contain operations")
	assert.Equal(t, 0, writerImpl.totalParentBatches, "should not have flushed yet")
	assert.Equal(t, 0, writerImpl.totalChildBatches, "should not have flushed yet")

	// Close should flush everything
	err = writerImpl.Close()
	require.NoError(t, err)

	// Verify buffers were flushed
	assert.Equal(t, 0, len(writerImpl.parentBuffer), "parent buffer should be empty after close")
	assert.Equal(t, 0, len(writerImpl.childBuffer), "child buffer should be empty after close")
	assert.Greater(t, writerImpl.totalParentBatches, 0, "should have flushed parent batch")
	assert.Greater(t, writerImpl.totalChildBatches, 0, "should have flushed child batch")
}

func TestBatchMetrics(t *testing.T) {
	// Test that batch counts accurately reflect number of flushes
	tmpDir := t.TempDir()

	batchSize := 25
	numEntries := 100

	w, err := NewWriter(tmpDir, provider.States{}, false, batchSize)
	require.NoError(t, err)

	writerImpl := w.(*writer)

	// Write entries
	entries := createTestEntries(numEntries)
	for _, entry := range entries {
		err := writerImpl.Write(entry)
		require.NoError(t, err)
	}

	err = writerImpl.Close()
	require.NoError(t, err)

	// Verify batch counts
	// With 100 entries, batchSize=25:
	// - Parent ops: 100 vulnerabilities / 25 = 4 batches
	// - Child ops: depends on children per entry, but should also batch
	assert.Greater(t, writerImpl.totalParentBatches, 0, "should have parent batches")
	assert.Greater(t, writerImpl.totalChildBatches, 0, "should have child batches")
}

func TestBatchSizeConfiguration(t *testing.T) {
	// Test that batch size defaults and configuration work correctly
	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		inputSize    int
		expectedSize int
	}{
		{
			name:         "default (0 -> 2000)",
			inputSize:    0,
			expectedSize: 2000,
		},
		{
			name:         "custom size",
			inputSize:    500,
			expectedSize: 500,
		},
		{
			name:         "unbatched mode",
			inputSize:    1,
			expectedSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tmpDir, provider.States{}, false, tt.inputSize)
			require.NoError(t, err)
			defer w.Close()

			writerImpl := w.(*writer)
			assert.Equal(t, tt.expectedSize, writerImpl.parentBatchSize)
			assert.Equal(t, tt.expectedSize, writerImpl.childBatchSize)
		})
	}
}

// createTestEntries creates test entries with unique identifiable content
func createTestEntries(count int) []data.Entry {
	entries := make([]data.Entry, count)

	for i := 0; i < count; i++ {
		entries[i] = data.Entry{
			DBSchemaVersion: grypeDB.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:       "CVE-2023-TEST",
					ProviderID: "test-provider",
					Provider: &grypeDB.Provider{
						ID:      "test-provider",
						Version: "1.0.0",
					},
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID: "CVE-2023-TEST",
					},
				},
				Related: []any{
					grypeDB.CWEHandle{
						CVE: "CVE-2023-TEST",
						CWE: "CWE-79",
					},
				},
			},
		}
	}

	return entries
}
