package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/tests"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

func mockMatchExclusionProcessorTransform(vulnerability unmarshal.MatchExclusion) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestMatchExclusionProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/exclusions.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewMatchExclusionProcessor(mockMatchExclusionProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "match-exclusions",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 3)
}
