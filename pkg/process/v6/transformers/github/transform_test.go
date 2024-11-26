package github

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func TestTransform(t *testing.T) {
	type counts struct {
		providerCount        int
		vulnerabilityCount   int
		affectedPackageCount int
	}

	tests := []struct {
		name       string
		fixture    string
		state      provider.State
		wantCounts counts
	}{
		{
			name:    "multiple fixed versions for Plone",
			fixture: "test-fixtures/multiple-fixed-in-names.json",
			state: provider.State{
				Provider:  "github",
				Version:   1,
				Timestamp: time.Date(2024, 03, 01, 12, 0, 0, 0, time.UTC),
			},
			wantCounts: counts{
				providerCount:        1,
				vulnerabilityCount:   1,
				affectedPackageCount: 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.fixture)
			require.Len(t, advisories, 1, "expected exactly one advisory")
			advisory := advisories[0]

			entries, err := Transform(advisory, tt.state)
			require.NoError(t, err)
			require.Len(t, entries, 1, "expected exactly one data.Entry")

			entry := entries[0]
			require.NotNil(t, entry.Data)

			data, ok := entry.Data.(transformers.RelatedEntries)
			require.True(t, ok, "expected entry.Data to be of type RelatedEntries")

			require.NotNil(t, data.Provider, "expected a Provider")
			require.Equal(t, tt.wantCounts.providerCount, 1)

			require.NotNil(t, data.VulnerabilityHandle, "expected a VulnerabilityHandle")
			require.Equal(t, tt.wantCounts.vulnerabilityCount, 1)

			require.Len(t, data.Related, tt.wantCounts.affectedPackageCount, "unexpected number of related entries")
		})
	}
}

func TestGetVulnerability(t *testing.T) {
	tests := []struct {
		name     string
		expected []grypeDB.VulnerabilityHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name: "GHSA-2wgc-48g2-cj5w",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:            "GHSA-2wgc-48g2-cj5w",
						ProviderName:  "github",
						Description:   "vantage6 has insecure SSH configuration for node and server containers",
						ModifiedDate:  internal.ParseTime("2024-02-08T22:48:31Z"),
						PublishedDate: internal.ParseTime("2024-01-30T20:56:46Z"),
						WithdrawnDate: nil,
						Status:        grypeDB.VulnerabilityActive,
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-2wgc-48g2-cj5w",
							},
						},
						Aliases: []string{"CVE-2024-21653"},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "medium",
							},
							{
								Scheme: grypeDB.SeveritySchemeCVSS,
								Value: grypeDB.CVSSSeverity{
									Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
									Version: "3.1",
									Score:   6.5,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/GHSA-3x74-v64j-qc3f.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name: "GHSA-3x74-v64j-qc3f",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:            "GHSA-3x74-v64j-qc3f",
						ProviderName:  "github",
						Description:   "Withdrawn Advisory: CraftCMS Server-Side Template Injection vulnerability",
						ModifiedDate:  internal.ParseTime("2024-03-21T17:48:19Z"),
						PublishedDate: internal.ParseTime("2023-06-13T18:30:39Z"),
						WithdrawnDate: internal.ParseTime("2023-06-28T23:54:39Z"),
						Status:        grypeDB.VulnerabilityRejected,
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-3x74-v64j-qc3f",
							},
						},
						Aliases: []string{"CVE-2023-30179"},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: grypeDB.SeveritySchemeCVSS,
								Value: grypeDB.CVSSSeverity{
									Vector:  "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
									Version: "3.1",
									Score:   9.8,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-npm-0.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name: "GHSA-vc9j-fhvv-8vrf",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:            "GHSA-vc9j-fhvv-8vrf",
						ProviderName:  "github",
						Description:   "Remote Code Execution in scratch-vm",
						ModifiedDate:  internal.ParseTime("2023-01-09T05:03:39Z"),
						PublishedDate: internal.ParseTime("2020-07-27T19:55:52Z"),
						WithdrawnDate: nil,
						Status:        grypeDB.VulnerabilityActive,
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-vc9j-fhvv-8vrf",
							},
						},
						Aliases: []string{"CVE-2020-14000"},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "critical",
							},
							{
								Scheme: grypeDB.SeveritySchemeCVSS,
								Value: grypeDB.CVSSSeverity{
									Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									Version: "3.1",
									Score:   9.8,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-python-0.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name: "GHSA-6cwv-x26c-w2q4",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:           "GHSA-6cwv-x26c-w2q4",
						ProviderName: "github",
						Status:       "active",
						Description:  "Low severity vulnerability that affects notebook",
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-6cwv-x26c-w2q4",
							},
						},

						Aliases: []string{"CVE-2018-8768"},

						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "low",
							},
						},
					},
				},
				{
					Name: "GHSA-p5wr-vp8g-q5p4",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:           "GHSA-p5wr-vp8g-q5p4",
						ProviderName: "github",
						Status:       "active",
						Description:  "Moderate severity vulnerability that affects Plone",
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
							},
						},
						Aliases: []string{"CVE-2017-5524"},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "medium",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-withdrawn.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name: "GHSA-6cwv-x26c-w2q4",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:            "GHSA-6cwv-x26c-w2q4",
						ProviderName:  "github",
						Description:   "Low severity vulnerability that affects notebook",
						ModifiedDate:  nil,
						PublishedDate: nil,
						WithdrawnDate: internal.ParseTime("2022-01-31T14:32:09Z"),
						Status:        grypeDB.VulnerabilityRejected,
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-6cwv-x26c-w2q4",
							},
						},
						Aliases: []string{"CVE-2018-8768"},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "low",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/multiple-fixed-in-names.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name: "GHSA-p5wr-vp8g-q5p4",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:           "GHSA-p5wr-vp8g-q5p4",
						ProviderName: "github",
						Description:  "Moderate severity vulnerability that affects Plone",
						Status:       grypeDB.VulnerabilityActive,
						References: []grypeDB.Reference{
							{
								URL: "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
							},
						},
						Aliases: []string{"CVE-2017-5524"},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "medium",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.name)
			var results []grypeDB.VulnerabilityHandle

			for _, advisory := range advisories {
				result := getVulnerability(advisory, "github")
				results = append(results, result)
			}
			if d := cmp.Diff(tt.expected, results); d != "" {
				t.Fatalf("unexpected result: %s", d)
			}
		})
	}
}

func TestGetAffectedPackage(t *testing.T) {
	tests := []struct {
		name     string
		expected []grypeDB.AffectedPackageHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []grypeDB.AffectedPackageHandle{
				{
					Package: &grypeDB.Package{
						Name: "vantage6",
						Type: "python",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2024-21653"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{
									Type:       "python",
									Constraint: "<4.2.0",
								},
								Fix: &grypeDB.Fix{
									Version: "4.2.0",
									State:   grypeDB.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/GHSA-3x74-v64j-qc3f.json",
			expected: []grypeDB.AffectedPackageHandle{
				{
					Package: &grypeDB.Package{
						Name: "craftcms/cms",
						Type: "packagist",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2023-30179"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{
									Type:       "packagist",
									Constraint: "<4.4.2",
								},
								Fix: &grypeDB.Fix{
									Version: "4.4.2",
									State:   grypeDB.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-npm-0.json",
			expected: []grypeDB.AffectedPackageHandle{
				{
					Package: &grypeDB.Package{
						Name: "scratch-vm",
						Type: "npm",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2020-14000"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{
									Type:       "npm",
									Constraint: "<=0.2.0-prerelease.20200709173451",
								},
								Fix: &grypeDB.Fix{
									Version: "0.2.0-prerelease.20200714185213",
									State:   grypeDB.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-python-0.json",
			expected: []grypeDB.AffectedPackageHandle{
				{
					Package: &grypeDB.Package{
						Type: "python",
						Name: "notebook",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs:       []string{"CVE-2018-8768"},
						Qualifiers: nil,
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{Type: "python", Constraint: "<5.4.1"},
								Fix:     &grypeDB.Fix{Version: "5.4.1", State: grypeDB.FixedStatus},
							},
						},
					},
				},
				{
					Package: &grypeDB.Package{
						Type: "python",
						Name: "Plone",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{Type: "python", Constraint: ">=4.0,<4.3.12"},
								Fix:     &grypeDB.Fix{Version: "4.3.12", State: grypeDB.FixedStatus},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/multiple-fixed-in-names.json",
			expected: []grypeDB.AffectedPackageHandle{
				{
					Package: &grypeDB.Package{
						Name: "Plone",
						Type: "python",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{
									Type:       "python",
									Constraint: ">=4.0,<4.3.12",
								},
								Fix: &grypeDB.Fix{
									Version: "4.3.12",
									State:   grypeDB.FixedStatus,
								},
							},
						},
					},
				},
				{
					Package: &grypeDB.Package{
						Name: "Plone",
						Type: "python",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{
									Type:       "python",
									Constraint: ">=5.1a1,<5.1b1",
								},
								Fix: &grypeDB.Fix{
									Version: "5.1b1",
									State:   grypeDB.FixedStatus,
								},
							},
						},
					},
				},
				{
					Package: &grypeDB.Package{
						Name: "Plone-debug",
						Type: "python",
					},
					BlobValue: &grypeDB.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []grypeDB.AffectedRange{
							{
								Version: grypeDB.AffectedVersion{
									Type:       "python",
									Constraint: ">=5.0rc1,<5.0.7",
								},
								Fix: &grypeDB.Fix{
									Version: "5.0.7",
									State:   grypeDB.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.name)
			var results []grypeDB.AffectedPackageHandle
			for _, advisor := range advisories {
				result := getAffectedPackage(advisor)
				results = append(results, result...)
			}
			if d := cmp.Diff(tt.expected, results); d != "" {
				t.Fatalf("unexpected result: %s", d)
			}
		})
	}
}

func loadFixture(t *testing.T, path string) []unmarshal.GitHubAdvisory {
	f, err := os.Open(path)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})
	require.NoError(t, err)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	require.NoError(t, err)

	return entries
}
