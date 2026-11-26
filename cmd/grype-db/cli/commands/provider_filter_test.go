package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/provider"
)

type fakeProvider string

func (f fakeProvider) ID() provider.Identifier {
	return provider.Identifier{Name: string(f)}
}

func (f fakeProvider) State() (*provider.State, error) {
	return nil, nil
}

func names(ps provider.Providers) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.ID().Name)
	}
	return out
}

func Test_filterProviders(t *testing.T) {
	configured := provider.Providers{fakeProvider("alpine"), fakeProvider("debian"), fakeProvider("nvd")}

	tests := []struct {
		name      string
		requested []string
		want      []string
		wantErr   string
	}{
		{
			name: "no filter keeps everything",
			want: []string{"alpine", "debian", "nvd"},
		},
		{
			name:      "all requested names match",
			requested: []string{"debian", "alpine"},
			want:      []string{"alpine", "debian"},
		},
		{
			name:      "duplicate requested names are fine",
			requested: []string{"nvd", "nvd"},
			want:      []string{"nvd"},
		},
		{
			name:      "a typo among valid names is an error, not a silently smaller set",
			requested: []string{"alpine", "debain"},
			wantErr:   "providers requested but not configured: debain",
		},
		{
			name:      "nothing matches",
			requested: []string{"ubuntu", "rhel"},
			wantErr:   "providers requested but not configured: rhel, ubuntu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterProviders(configured, tt.requested)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, names(got))
		})
	}
}
