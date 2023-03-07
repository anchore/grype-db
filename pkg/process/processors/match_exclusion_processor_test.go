package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/data"
	testUtils "github.com/anchore/grype-db/pkg/process/tests"
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
	defer testUtils.CloseFile(f)

	processor := NewMatchExclusionProcessor(mockMatchExclusionProcessorTransform)
	entries, err := processor.Process(f)

	require.NoError(t, err)
	assert.Len(t, entries, 3)
}
