package osv

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	grypeDB "github.com/anchore/grype/grype/db/v5"
)

func TestTransform(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantVulns    []grypeDB.Vulnerability
		wantMetadata grypeDB.VulnerabilityMetadata
		wantErr      bool
	}{
		{
			name:    "normal osv vulnerability",
			fixture: "bitnami-2021-31957.json",
			wantMetadata: grypeDB.VulnerabilityMetadata{
				ID:           "BIT-dotnet-2021-31957",
				Namespace:    "bitnami:purl", // TODO: is this what we want?
				DataSource:   "",             // TODO: what goes here? Does vunnel need to build a github raw link or something?
				RecordSource: "bitnami:purl", // TODO: is this right?
				Severity:     "Medium",
				URLs: []string{
					// TODO: data source too, once we know what that is
					"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CVCDYIP4A6DDRT7G6P3ZW6PKNK2DNWJ2/",
					"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4PRVVLXXQEF4SEJOBV3VRJHGX7YHY2CG/",
					"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PMHWHRRYDHKM6BIINW5V7OCSW4SDWB4W/",
					"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VMAO4NG2OQ4PCXUQWMNSCMYWLIJJY6UY/",
					"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-31957",
				},
				Description: "ASP.NET Core Denial of Service Vulnerability",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.CvssMetrics{},
						Vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
						Version: "3.1",
						Type:    "CVSS_V3",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixturePath := filepath.Join("test-fixtures", tt.fixture)
			r, err := os.Open(fixturePath)
			require.NoError(t, err)
			entries, err := unmarshal.OSVVulnerabilityEntries(r)
			require.NoError(t, err)
			vulns, meta, err := transformImpl(entries[0])
			if tt.wantErr {
				require.Error(t, err)
			}
			require.NoError(t, err)
			if diff := cmp.Diff(tt.wantVulns, vulns); diff != "" {
				t.Errorf("wrong vulns +got -want %s\n", diff)
			}
			if diff := cmp.Diff(tt.wantMetadata, meta); diff != "" {
				t.Errorf("wrong metadata +got -want %s\n", diff)
			}
		})
	}
}

func mustTime(t time.Time, err error) time.Time {
	if err != nil {
		panic(err)
	}
	return t
}
