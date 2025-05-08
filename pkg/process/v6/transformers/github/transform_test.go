package github

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/syft/syft/pkg"
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

			require.NotNil(t, data.VulnerabilityHandle, "expected a VulnerabilityHandle")
			require.Equal(t, tt.wantCounts.vulnerabilityCount, 1)

			require.Len(t, data.Related, tt.wantCounts.affectedPackageCount, "unexpected number of related entries")
		})
	}
}

func TestGetVulnerability(t *testing.T) {
	now := time.Date(2024, 03, 01, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		expected []grypeDB.VulnerabilityHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []grypeDB.VulnerabilityHandle{
				{
					Name:       "GHSA-2wgc-48g2-cj5w",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-02-08T22:48:31Z"),
					PublishedDate: internal.ParseTime("2024-01-30T20:56:46Z"),
					WithdrawnDate: nil,
					Status:        grypeDB.VulnerabilityActive,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-2wgc-48g2-cj5w",
						Description: "vantage6 has insecure SSH configuration for node and server containers",
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
					Name:       "GHSA-3x74-v64j-qc3f",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-03-21T17:48:19Z"),
					PublishedDate: internal.ParseTime("2023-06-13T18:30:39Z"),
					WithdrawnDate: internal.ParseTime("2023-06-28T23:54:39Z"),
					Status:        grypeDB.VulnerabilityRejected,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-3x74-v64j-qc3f",
						Description: "Withdrawn Advisory: CraftCMS Server-Side Template Injection vulnerability",
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
					Name:       "GHSA-vc9j-fhvv-8vrf",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2023-01-09T05:03:39Z"),
					PublishedDate: internal.ParseTime("2020-07-27T19:55:52Z"),
					WithdrawnDate: nil,
					Status:        grypeDB.VulnerabilityActive,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-vc9j-fhvv-8vrf",
						Description: "Remote Code Execution in scratch-vm",
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
					Name:       "GHSA-6cwv-x26c-w2q4",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: "active",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-6cwv-x26c-w2q4",
						Description: "Low severity vulnerability that affects notebook",
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
					Name:       "GHSA-p5wr-vp8g-q5p4",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: "active",
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-p5wr-vp8g-q5p4",
						Description: "Moderate severity vulnerability that affects Plone",
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
					Name:       "GHSA-6cwv-x26c-w2q4",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  nil,
					PublishedDate: nil,
					WithdrawnDate: internal.ParseTime("2022-01-31T14:32:09Z"),
					Status:        grypeDB.VulnerabilityRejected,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-6cwv-x26c-w2q4",
						Description: "Low severity vulnerability that affects notebook",
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
					Name:       "GHSA-p5wr-vp8g-q5p4",
					ProviderID: "github",
					Provider: &grypeDB.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: grypeDB.VulnerabilityActive,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "GHSA-p5wr-vp8g-q5p4",
						Description: "Moderate severity vulnerability that affects Plone",
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
				result := getVulnerability(advisory, provider.State{Provider: "github", Version: 1, Timestamp: now})
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
						Name:      "vantage6",
						Ecosystem: "python",
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
						Name:      "craftcms/cms",
						Ecosystem: "packagist",
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
						Name:      "scratch-vm",
						Ecosystem: "npm",
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
						Ecosystem: "python",
						Name:      "notebook",
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
						Ecosystem: "python",
						Name:      "Plone",
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
						Name:      "Plone",
						Ecosystem: "python",
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
						Name:      "Plone",
						Ecosystem: "python",
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
						Name:      "Plone-debug",
						Ecosystem: "python",
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

func TestGetPackageType(t *testing.T) {
	tests := []struct {
		ecosystem    string
		expectedType pkg.Type
	}{
		{"composer", pkg.PhpComposerPkg},
		{"Composer", pkg.PhpComposerPkg}, // testing case insensitivity
		{"COMPOSER", pkg.PhpComposerPkg}, // testing case insensitivity
		{"rust", pkg.RustPkg},
		{"cargo", pkg.RustPkg},
		{"dart", pkg.DartPubPkg},
		{"nuget", pkg.DotnetPkg},
		{".net", pkg.DotnetPkg},
		{"go", pkg.GoModulePkg},
		{"golang", pkg.GoModulePkg},
		{"maven", pkg.JavaPkg},
		{"java", pkg.JavaPkg},
		{"npm", pkg.NpmPkg},
		{"pypi", pkg.PythonPkg},
		{"python", pkg.PythonPkg},
		{"pip", pkg.PythonPkg},
		{"swift", pkg.SwiftPkg},
		{"rubygems", pkg.GemPkg},
		{"ruby", pkg.GemPkg},
		{"gem", pkg.GemPkg},
		{"apk", pkg.ApkPkg},
		{"rpm", pkg.RpmPkg},
		{"deb", pkg.DebPkg},
		{"github-action", pkg.GithubActionPkg},

		// test for unknown type fallback
		{"unknown-ecosystem", pkg.Type("unknown-ecosystem")},
		{"", pkg.Type("")},
	}

	for _, tc := range tests {
		t.Run(tc.ecosystem, func(t *testing.T) {
			gotType := getPackageType(tc.ecosystem)
			if gotType != tc.expectedType {
				t.Errorf("getPackageType(%q) = %v, want %v", tc.ecosystem, gotType, tc.expectedType)
			}
		})
	}
}

func TestGetRanges(t *testing.T) {
	advisories := loadFixture(t, "test-fixtures/GHSA-92cp-5422-2mw7.json")
	require.Len(t, advisories, 1)
	advisory := advisories[0]
	var ranges []grypeDB.AffectedRange
	expectedRanges := []grypeDB.AffectedRange{
		{
			Version: grypeDB.AffectedVersion{
				Type:       "go",
				Constraint: ">=9.7.0-beta.1,<9.7.3",
			},
			Fix: &grypeDB.Fix{
				Version: "9.7.3",
				State:   grypeDB.FixedStatus,
			},
		},
		{
			Version: grypeDB.AffectedVersion{
				// important: this emits an unknown constraint type,
				// triggering fuzzy matching when the input is not
				// valid semver
				Type:       "Unknown",
				Constraint: ">=9.6.0b1,<9.6.3",
			},
			Fix: &grypeDB.Fix{
				Version: "9.6.3",
				State:   grypeDB.FixedStatus,
			},
		},
		{
			Version: grypeDB.AffectedVersion{
				Type:       "go",
				Constraint: ">=9.5.1,<9.5.5",
			},
			Fix: &grypeDB.Fix{
				Version: "9.5.5",
				State:   grypeDB.FixedStatus,
			},
		},
	}
	var errors []error
	for _, fixedIn := range advisory.Advisory.FixedIn {
		rng, err := getRanges(fixedIn)
		if err != nil {
			errors = append(errors, err)
		}
		ranges = append(ranges, rng...)
	}

	assert.Equal(t, 1, len(errors))
	assert.ErrorIs(t, errors[0], version.ErrFallbackToFuzzy)
	if diff := cmp.Diff(expectedRanges, ranges); diff != "" {
		t.Errorf("getRanges() mismatch (-want +got):\n%s", diff)
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
