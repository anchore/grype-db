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
	defer testUtils.CloseFile(f)

	processor := NewGitHubProcessor(mockGithubProcessorTransform)
	entries, err := processor.Process(f)

	assert.NoError(t, err)
	assert.Len(t, entries, 3)
}
