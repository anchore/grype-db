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

func mockOSVProcessorTransform(vulnerability unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestV2OSVProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/osv.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewV2OSVProcessor(mockOSVProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "osv",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 2)
}
