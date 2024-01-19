package v3

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype-db/pkg/db/v3"
)

var _ grypeDB.VulnerabilityMetadataStoreReader = (*mockReader)(nil)

type mockReader struct {
	metadata *grypeDB.VulnerabilityMetadata
	err      error
}

func newMockReader(sev string) *mockReader {
	return &mockReader{
		metadata: &grypeDB.VulnerabilityMetadata{
			Severity:  sev,
			Namespace: "nvd",
		},
	}
}

func newDeadMockReader() *mockReader {
	return &mockReader{
		err: errors.New("dead"),
	}
}

func (m mockReader) GetVulnerabilityMetadata(_, _ string) (*grypeDB.VulnerabilityMetadata, error) {
	return m.metadata, m.err
}

func (m mockReader) GetAllVulnerabilityMetadata() (*[]grypeDB.VulnerabilityMetadata, error) {
	panic("implement me")
}

func Test_normalizeSeverity(t *testing.T) {

	tests := []struct {
		name            string
		initialSeverity string
		namespace       string
		cveID           string
		reader          grypeDB.VulnerabilityMetadataStoreReader
		expected        data.Severity
	}{
		{
			name:            "skip missing metadata",
			initialSeverity: "",
			namespace:       "test",
			reader:          &mockReader{},
			expected:        "",
		},
		{
			name:            "skip non-cve records metadata",
			cveID:           "GHSA-1234-1234-1234",
			initialSeverity: "",
			namespace:       "test",
			reader:          newDeadMockReader(), // should not be used
			expected:        "",
		}, {
			name:            "override empty severity",
			initialSeverity: "",
			namespace:       "test",
			reader:          newMockReader("low"),
			expected:        data.SeverityLow,
		},
		{
			name:            "override unknown severity",
			initialSeverity: "unknown",
			namespace:       "test",
			reader:          newMockReader("low"),
			expected:        data.SeverityLow,
		},
		{
			name:            "ignore record with severity already set",
			initialSeverity: "Low",
			namespace:       "test",
			reader:          newMockReader("critical"), // should not be used
			expected:        data.SeverityLow,
		},
		{
			name:            "ignore nvd records",
			initialSeverity: "Low",
			namespace:       "nvd",
			reader:          newDeadMockReader(), // should not be used
			expected:        data.SeverityLow,
		},
		{
			name:            "db errors should not fail or modify the record",
			initialSeverity: "",
			namespace:       "test",
			reader:          newDeadMockReader(),
			expected:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &grypeDB.VulnerabilityMetadata{
				ID:        "cve-2020-0000",
				Severity:  tt.initialSeverity,
				Namespace: tt.namespace,
			}
			if tt.cveID != "" {
				record.ID = tt.cveID
			}
			normalizeSeverity(record, tt.reader)
			assert.Equal(t, string(tt.expected), record.Severity)
		})
	}
}
