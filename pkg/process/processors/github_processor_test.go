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

func mockGithubProcessorTransform(vulnerability unmarshal.GitHubAdvisory) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestGitHubProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/github.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewGitHubProcessor(mockGithubProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "github",
	})

	assert.NoError(t, err)
	assert.Len(t, entries, 3)
}
