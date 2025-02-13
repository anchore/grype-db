package v6

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		name              string
		handle            *grypeDB.VulnerabilityHandle
		severityCache     map[string]grypeDB.Severity
		expected          []grypeDB.Severity
		expectCacheUpdate bool
	}{
		{
			name:          "nil handle",
			handle:        nil,
			severityCache: map[string]grypeDB.Severity{},
			expected:      nil,
		},
		{
			name: "nil metadata",
			handle: &grypeDB.VulnerabilityHandle{
				BlobValue: nil,
			},
			severityCache: map[string]grypeDB.Severity{},
			expected:      nil,
		},
		{
			name: "non-CVE ID",
			handle: &grypeDB.VulnerabilityHandle{
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID: "GHSA-123",
					Severities: []grypeDB.Severity{
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]grypeDB.Severity{},
			expected:      []grypeDB.Severity{{Value: "high"}},
		},
		{
			name: "NVD provider with CVE",
			handle: &grypeDB.VulnerabilityHandle{
				ProviderID: "nvd",
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID: "CVE-2023-1234",
					Severities: []grypeDB.Severity{
						{Value: "critical"},
					},
				},
			},
			severityCache:     map[string]grypeDB.Severity{},
			expected:          []grypeDB.Severity{{Value: "critical"}},
			expectCacheUpdate: true,
		},
		{
			name: "CVE with existing severities",
			handle: &grypeDB.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID: "CVE-2023-5678",
					Severities: []grypeDB.Severity{
						{Value: "medium"},
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]grypeDB.Severity{
				"cve-2023-5678": {Value: "critical"},
			},
			expected: []grypeDB.Severity{
				{Value: "medium"},
				{Value: "high"},
			},
		},
		{
			name: "CVE with no severities, using cache",
			handle: &grypeDB.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID:         "CVE-2023-9012",
					Severities: []grypeDB.Severity{},
				},
			},
			severityCache: map[string]grypeDB.Severity{
				"cve-2023-9012": {Value: "high"},
			},
			expected: []grypeDB.Severity{{Value: "high"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &writer{
				severityCache: tt.severityCache,
			}

			if tt.expectCacheUpdate {
				// assert expected ids are not in the cache
				if tt.handle != nil && tt.handle.BlobValue != nil {
					assert.NotContains(t, tt.severityCache, strings.ToLower(tt.handle.BlobValue.ID))
				}
			}

			w.normalizeSeverity(tt.handle)

			if tt.handle == nil || tt.handle.BlobValue == nil {
				return
			}

			if tt.expectCacheUpdate {
				// assert expected ids are not in the cache
				if tt.handle != nil && tt.handle.BlobValue != nil {
					id := strings.ToLower(tt.handle.BlobValue.ID)
					assert.Equal(t, tt.severityCache[id], w.severityCache[id])
				}
			}

			assert.Equal(t, tt.expected, tt.handle.BlobValue.Severities)
		})
	}
}

func TestFilterUnknownSeverities(t *testing.T) {
	tests := []struct {
		name     string
		input    []grypeDB.Severity
		expected []grypeDB.Severity
	}{
		{
			name:     "empty input",
			input:    []grypeDB.Severity{},
			expected: nil,
		},
		{
			name: "all known severities",
			input: []grypeDB.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
			expected: []grypeDB.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "mix of known and unknown",
			input: []grypeDB.Severity{
				{Value: "high"},
				{Value: "unknown"},
				{Value: "medium"},
				{Value: ""},
			},
			expected: []grypeDB.Severity{
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "non-string values",
			input: []grypeDB.Severity{
				{Value: 5},
				{Value: nil},
				{Value: "high"},
			},
			expected: []grypeDB.Severity{
				{Value: 5},
				{Value: "high"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterUnknownSeverities(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsKnownSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity grypeDB.Severity
		expected bool
	}{
		{
			name:     "empty string",
			severity: grypeDB.Severity{Value: ""},
			expected: false,
		},
		{
			name:     "unknown string",
			severity: grypeDB.Severity{Value: "unknown"},
			expected: false,
		},
		{
			name:     "case insensitive",
			severity: grypeDB.Severity{Value: "UNKNOWN"},
			expected: false,
		},
		{
			name:     "valid string severity",
			severity: grypeDB.Severity{Value: "high"},
			expected: true,
		},
		{
			name:     "nil value",
			severity: grypeDB.Severity{Value: nil},
			expected: false,
		},
		{
			name:     "numeric value",
			severity: grypeDB.Severity{Value: 7},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isKnownSeverity(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}
