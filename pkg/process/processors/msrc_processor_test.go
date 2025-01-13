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

func mockMSRCProcessorTransform(vulnerability unmarshal.MSRCVulnerability) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestMSRCProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/msrc.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewMSRCProcessor(mockMSRCProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "msrc",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestMsrcProcessor_IsSupported(t *testing.T) {
	tc := []struct {
		name      string
		schemaURL string
		expected  bool
	}{
		{
			name:      "valid schema URL with version 1.0.0",
			schemaURL: "https://example.com/vunnel/path/vulnerability/msrc/schema-1.0.0.json",
			expected:  true,
		},
		{
			name:      "valid schema URL with version 1.2.3",
			schemaURL: "https://example.com/vunnel/path/vulnerability/msrc/schema-1.2.3.json",
			expected:  true,
		},
		{
			name:      "invalid schema URL with unsupported version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/msrc/schema-2.0.0.json",
			expected:  false,
		},
		{
			name:      "invalid schema URL with missing version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/msrc/schema.json",
			expected:  false,
		},
		{
			name:      "completely invalid URL",
			schemaURL: "https://example.com/invalid/schema/url",
			expected:  false,
		},
	}

	p := msrcProcessor{}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.IsSupported(tt.schemaURL))
		})
	}
}
