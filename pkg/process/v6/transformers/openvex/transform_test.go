package openvex

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

var timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
var listing = provider.File{
	Path:      "some",
	Digest:    "123456",
	Algorithm: "sha256",
}

func inputProviderState() provider.State {
	return provider.State{
		Provider:  "openvex",
		Version:   1,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func TestOpenVEXTransform(t *testing.T) {
	tests := []struct {
		name    string
		state   provider.State
		vuln    unmarshal.OpenVEXVulnerability
		wantErr bool
		want    transformers.RelatedEntries
	}{
		{
			name:  "basic OpenVEX vulnerability with single product",
			state: inputProviderState(),
			vuln: govex.Statement{
				ID: "test-transform-1",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:pypi/urllib3@1.26.16",
							},
						},
					},
				},
				Status: govex.StatusAffected,
				Vulnerability: govex.Vulnerability{
					Name:        "cve-2023-43804",
					Description: "urllib3 HTTP Request Smuggling vulnerability",
					Aliases:     []govex.VulnerabilityID{"ghsa-v845-jxx5-vc9f"},
				},
			},
			want: transformers.RelatedEntries{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:       "cve-2023-43804",
					Status:     grypeDB.VulnerabilityActive,
					ProviderID: "openvex",
					Provider: &grypeDB.Provider{
						ID:           "openvex",
						Version:      "1",
						Processor:    "vunnel@1.2.3",
						DateCaptured: &timeVal,
						InputDigest:  "sha256:123456",
					},
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "cve-2023-43804",
						Description: "urllib3 HTTP Request Smuggling vulnerability",
						References: []grypeDB.Reference{
							{
								URL: "cve-2023-43804",
							},
						},
						Aliases: []string{"ghsa-v845-jxx5-vc9f"},
					},
				},
				Related: []any{
					grypeDB.AffectedPackageHandle{
						Package: &grypeDB.Package{
							// convert pypi -> python
							Ecosystem: "python",
							Name:      "urllib3",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
							Ranges: []grypeDB.Range{
								{
									Version: grypeDB.Version{
										Type:       "semver",
										Constraint: "== 1.26.16",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:  "OpenVEX vulnerability with multiple products",
			state: inputProviderState(),
			vuln: govex.Statement{
				ID: "test-transform-2",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:pypi/urllib3@1.26.16",
							},
						},
					},
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:npm/express@4.18.2",
							},
						},
					},
				},
				Status: govex.StatusNotAffected,
				Vulnerability: govex.Vulnerability{
					Name:        "cve-2023-43804",
					Description: "Test vulnerability affecting multiple packages",
					Aliases:     []govex.VulnerabilityID{"ghsa-v845-jxx5-vc9f"},
				},
			},
			want: transformers.RelatedEntries{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:       "cve-2023-43804",
					Status:     grypeDB.VulnerabilityActive,
					ProviderID: "openvex",
					Provider: &grypeDB.Provider{
						ID:           "openvex",
						Version:      "1",
						Processor:    "vunnel@1.2.3",
						DateCaptured: &timeVal,
						InputDigest:  "sha256:123456",
					},
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "cve-2023-43804",
						Description: "Test vulnerability affecting multiple packages",
						References: []grypeDB.Reference{
							{
								URL: "cve-2023-43804",
							},
						},
						Aliases: []string{"ghsa-v845-jxx5-vc9f"},
					},
				},
				Related: []any{
					grypeDB.UnaffectedPackageHandle{
						Package: &grypeDB.Package{
							Ecosystem: "npm",
							Name:      "express",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
							Ranges: []grypeDB.Range{
								{
									Fix: &grypeDB.Fix{
										Version: "4.18.2",
										State:   grypeDB.NotAffectedFixStatus,
									},
								},
							},
						},
					},
					grypeDB.UnaffectedPackageHandle{
						Package: &grypeDB.Package{
							// convert pypi -> python
							Ecosystem: "python",
							Name:      "urllib3",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
							Ranges: []grypeDB.Range{
								{
									Fix: &grypeDB.Fix{
										Version: "1.26.16",
										State:   grypeDB.NotAffectedFixStatus,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:  "OpenVEX vulnerability with no products",
			state: inputProviderState(),
			vuln: govex.Statement{
				ID:       "test-transform-3",
				Products: []govex.Product{},
				Status:   govex.StatusNotAffected,
				Vulnerability: govex.Vulnerability{
					Name:        "cve-2023-43804",
					Description: "Test vulnerability with no products",
				},
			},
			want: transformers.RelatedEntries{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:       "cve-2023-43804",
					Status:     grypeDB.VulnerabilityActive,
					ProviderID: "openvex",
					Provider: &grypeDB.Provider{
						ID:           "openvex",
						Version:      "1",
						Processor:    "vunnel@1.2.3",
						DateCaptured: &timeVal,
						InputDigest:  "sha256:123456",
					},
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "cve-2023-43804",
						Description: "Test vulnerability with no products",
						References: []grypeDB.Reference{
							{
								URL: "cve-2023-43804",
							},
						},
						Aliases: []string{},
					},
				},
			},
		},
		{
			name:  "OpenVEX vulnerability with invalid product purl",
			state: inputProviderState(),
			vuln: govex.Statement{
				ID: "test-transform-4",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "invalid-purl",
							},
						},
					},
				},
				Status: govex.StatusAffected,
				Vulnerability: govex.Vulnerability{
					Name:        "cve-2023-43804",
					Description: "Test vulnerability with invalid purl",
				},
			},
			wantErr: true,
		},
		{
			name:  "OpenVEX vulnerability with empty product",
			state: inputProviderState(),
			vuln: govex.Statement{
				ID:       "test-transform-4",
				Products: []govex.Product{{}},
				Status:   govex.StatusAffected,
				Vulnerability: govex.Vulnerability{
					Name:        "cve-2023-43804",
					Description: "Test vulnerability with invalid purl",
				},
			},
			wantErr: true,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Transform(tt.vuln, tt.state)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, 1, "should return exactly one RelatedEntries")

			e, ok := got[0].Data.(transformers.RelatedEntries)
			require.True(t, ok)
			if diff := cmp.Diff(tt.want, e); diff != "" {
				t.Errorf("data entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_GetPackageHandles(t *testing.T) {
	tests := []struct {
		name    string
		vuln    unmarshal.OpenVEXVulnerability
		want    []any
		wantErr bool
	}{
		{
			name: "empty products returns nil",
			vuln: govex.Statement{
				ID:       "test-vuln-1",
				Products: []govex.Product{},
				Status:   govex.StatusAffected,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "single affected product",
			vuln: govex.Statement{
				ID: "test-vuln-2",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:pypi/urllib3@1.26.16",
							},
						},
					},
				},
				Status: govex.StatusAffected,
				Vulnerability: govex.Vulnerability{
					Name:    "cve-2023-43804",
					Aliases: []govex.VulnerabilityID{"ghsa-v845-jxx5-vc9f"},
				},
			},
			want: []any{
				grypeDB.AffectedPackageHandle{
					Package: &grypeDB.Package{
						// converts pypi -> python
						Ecosystem: "python",
						Name:      "urllib3",
					},
					BlobValue: &grypeDB.PackageBlob{
						CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
						Ranges: []grypeDB.Range{
							{
								Version: grypeDB.Version{
									Type:       "semver",
									Constraint: "== 1.26.16",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple products sorted alphabetically",
			vuln: govex.Statement{
				ID: "test-vuln-3",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:pypi/urllib3@1.26.16",
							},
						},
					},
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:npm/express@4.18.2",
							},
						},
					},
				},
				Status: govex.StatusNotAffected,
				Vulnerability: govex.Vulnerability{
					Name:    "cve-2023-43804",
					Aliases: []govex.VulnerabilityID{"ghsa-v845-jxx5-vc9f"},
				},
			},
			want: []any{
				grypeDB.UnaffectedPackageHandle{
					Package: &grypeDB.Package{
						Ecosystem: "npm",
						Name:      "express",
					},
					BlobValue: &grypeDB.PackageBlob{
						CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
						Ranges: []grypeDB.Range{
							{
								Fix: &grypeDB.Fix{
									Version: "4.18.2",
									State:   grypeDB.NotAffectedFixStatus,
								},
							},
						},
					},
				},
				grypeDB.UnaffectedPackageHandle{
					Package: &grypeDB.Package{
						// converts pypi -> python
						Ecosystem: "python",
						Name:      "urllib3",
					},
					BlobValue: &grypeDB.PackageBlob{
						CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
						Ranges: []grypeDB.Range{
							{
								Fix: &grypeDB.Fix{
									Version: "1.26.16",
									State:   grypeDB.NotAffectedFixStatus,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "fixed status product",
			vuln: govex.Statement{
				ID: "test-vuln-4",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "pkg:pypi/urllib3@2.0.7",
							},
						},
					},
				},
				Status: govex.StatusFixed,
				Vulnerability: govex.Vulnerability{
					Name:    "cve-2023-43804",
					Aliases: []govex.VulnerabilityID{"ghsa-v845-jxx5-vc9f"},
				},
			},
			want: []any{
				grypeDB.AffectedPackageHandle{
					Package: &grypeDB.Package{
						// converts pypi -> python
						Ecosystem: "python",
						Name:      "urllib3",
					},
					BlobValue: &grypeDB.PackageBlob{
						CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
						Ranges: []grypeDB.Range{
							{
								Version: grypeDB.Version{
									Type:       "semver",
									Constraint: "< 2.0.7",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid purl returns error",
			vuln: govex.Statement{
				ID: "test-vuln-5",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "invalid-purl",
							},
						},
					},
				},
				Status: govex.StatusAffected,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPackageHandles(&tt.vuln)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetPackages() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_GetUnaffectedPackage(t *testing.T) {
	tests := []struct {
		name    string
		product govex.Product
		vuln    unmarshal.OpenVEXVulnerability
		want    any
		wantErr bool
	}{
		{
			name:    "Empty results in error",
			product: govex.Product{},
			vuln:    unmarshal.OpenVEXVulnerability{},
			wantErr: true,
		},
		{
			name: "valid product and vuln",
			product: govex.Product{
				Component: govex.Component{
					Identifiers: map[govex.IdentifierType]string{
						govex.PURL: "pkg:pypi/urllib3@1.26.16",
					},
				},
			},
			vuln: govex.Statement{
				Status: govex.StatusAffected,
				Vulnerability: govex.Vulnerability{
					Name:    "cve-2023-43804",
					Aliases: []govex.VulnerabilityID{"ghsa-v845-jxx5-vc9f"},
				},
			},
			want: grypeDB.AffectedPackageHandle{
				Package: &grypeDB.Package{
					// converts pypi -> python
					Ecosystem: "python",
					Name:      "urllib3",
				},
				BlobValue: &grypeDB.PackageBlob{
					CVEs: []string{"cve-2023-43804", "ghsa-v845-jxx5-vc9f"},
					Ranges: []grypeDB.Range{
						{
							Version: grypeDB.Version{
								Type:       "semver",
								Constraint: "== 1.26.16",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid purl returns error",
			vuln: govex.Statement{
				ID: "test-vuln-5",
				Products: []govex.Product{
					{
						Component: govex.Component{
							Identifiers: map[govex.IdentifierType]string{
								govex.PURL: "invalid-purl",
							},
						},
					},
				},
				Status: govex.StatusAffected,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPackageHandle(&tt.product, &tt.vuln)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetPackages() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
