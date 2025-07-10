package providers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/providers/vunnel"
)

// mockProvider is a simple mock implementation of provider.Provider for testing
type mockProvider struct {
	name string
}

func (m mockProvider) ID() provider.Identifier {
	return provider.Identifier{Name: m.name}
}

func (m mockProvider) GetProviderState() provider.State {
	return provider.State{}
}

func (m mockProvider) GetSchemaVersion() int {
	return 1
}

func (m mockProvider) GetWorkspace() string {
	return ""
}

func (m mockProvider) Close() error {
	return nil
}

func TestNew_ProviderOrdering(t *testing.T) {
	tests := []struct {
		name             string
		providerNames    []string
		expectedOrdering []string
	}{
		{
			name:             "nvd first, github second",
			providerNames:    []string{"other1", "github", "nvd", "other2"},
			expectedOrdering: []string{"nvd", "github", "other1", "other2"},
		},
		{
			name:             "only nvd",
			providerNames:    []string{"nvd"},
			expectedOrdering: []string{"nvd"},
		},
		{
			name:             "only github",
			providerNames:    []string{"github"},
			expectedOrdering: []string{"github"},
		},
		{
			name:             "no nvd or github",
			providerNames:    []string{"other1", "other2", "other3"},
			expectedOrdering: []string{"other1", "other2", "other3"},
		},
		{
			name:             "nvd and github only",
			providerNames:    []string{"github", "nvd"},
			expectedOrdering: []string{"nvd", "github"},
		},
		{
			name:             "multiple others with nvd and github",
			providerNames:    []string{"alpine", "github", "debian", "nvd", "ubuntu", "centos"},
			expectedOrdering: []string{"nvd", "github", "alpine", "debian", "ubuntu", "centos"},
		},
		{
			name:             "reverse alphabetical input",
			providerNames:    []string{"ubuntu", "nvd", "github", "debian", "alpine"},
			expectedOrdering: []string{"nvd", "github", "ubuntu", "debian", "alpine"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock configs for each provider name
			var configs []provider.Config
			for _, name := range tt.providerNames {
				configs = append(configs, provider.Config{
					Identifier: provider.Identifier{
						Name: name,
						Kind: provider.VunnelKind,
					},
				})
			}

			// Call New with mock vunnel config
			vCfg := vunnel.Config{
				GenerateConfigs: false, // Don't generate additional configs for this test
			}

			providers, err := New("test-root", vCfg, configs...)
			require.NoError(t, err)
			require.Len(t, providers, len(tt.expectedOrdering))

			// Verify the ordering
			var actualOrdering []string
			for _, p := range providers {
				actualOrdering = append(actualOrdering, p.ID().Name)
			}

			require.Equal(t, tt.expectedOrdering, actualOrdering)
		})
	}
}

func TestNew_EmptyConfigs(t *testing.T) {
	vCfg := vunnel.Config{GenerateConfigs: false}
	_, err := New("test-root", vCfg)
	require.Error(t, err)
	require.Equal(t, ErrNoProviders, err)
}
