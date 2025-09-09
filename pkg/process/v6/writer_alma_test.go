package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/anchore/grype-db/pkg/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

// TestAlmaLinuxAliasFinalization tests the conditional AlmaLinux alias logic
func TestAlmaLinuxAliasFinalization(t *testing.T) {
	tests := []struct {
		name                string
		hasAlmaProvider     bool
		expectedRHELAliases []string // aliases that should point to "rhel"
		expectedAlmaAliases []string // aliases that should point to "almalinux"
	}{
		{
			name:                "no AlmaLinux provider - keep RHEL aliases",
			hasAlmaProvider:     false,
			expectedRHELAliases: []string{"alma", "almalinux"},
			expectedAlmaAliases: []string{},
		},
		{
			name:                "AlmaLinux provider exists - remove RHEL aliases, add alma->almalinux",
			hasAlmaProvider:     true,
			expectedRHELAliases: []string{}, // should be removed
			expectedAlmaAliases: []string{"alma"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test database
			tmp := t.TempDir()
			w, err := NewWriter(tmp, provider.States{})
			require.NoError(t, err)
			defer func() {
				assert.NoError(t, w.Close())
			}()

			writer := w.(*writer)

			// Add AlmaLinux provider if test requires it
			if tt.hasAlmaProvider {
				almaProvider := grypeDB.Provider{
					ID:           "almalinux",
					DateCaptured: nil,
					Version:      "",
				}
				err := writer.store.AddProvider(almaProvider)
				require.NoError(t, err)
			}

			// Test the override writing logic
			err = writer.writeOverrides()
			require.NoError(t, err)

			// Verify the aliases are correct
			checkAliases(t, writer, tt.expectedRHELAliases, "rhel")
			checkAliases(t, writer, tt.expectedAlmaAliases, "almalinux")
		})
	}
}

func checkAliases(t *testing.T, writer *writer, expectedAliases []string, expectedReplacement string) {
	type lowLevelReader interface {
		GetDB() *gorm.DB
	}

	db := writer.store.(lowLevelReader).GetDB()

	for _, alias := range expectedAliases {
		var override grypeDB.OperatingSystemSpecifierOverride
		err := db.Where("alias = ? AND replacement = ?", alias, expectedReplacement).
			First(&override).Error

		require.NoError(t, err, "expected alias %s -> %s to exist", alias, expectedReplacement)
		assert.Equal(t, alias, override.Alias)
		assert.Equal(t, expectedReplacement, *override.ReplacementName)
	}
}
