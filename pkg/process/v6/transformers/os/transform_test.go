package os

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/process/v6/internal/tests"
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

func inputProviderState(name string) provider.State {
	return provider.State{
		Provider:  name,
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider(name string) *grypeDB.Provider {
	return &grypeDB.Provider{
		ID:           name,
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func TestTransform(t *testing.T) {

	alpineOS := &grypeDB.OperatingSystem{
		Name:         "alpine",
		ReleaseID:    "alpine",
		MajorVersion: "3",
		MinorVersion: "9",
	}

	amazonOS := &grypeDB.OperatingSystem{
		Name:         "amazonlinux",
		ReleaseID:    "amzn",
		MajorVersion: "2",
	}
	azure3OS := &grypeDB.OperatingSystem{
		Name:         "azurelinux",
		ReleaseID:    "azurelinux",
		MajorVersion: "3",
		MinorVersion: "0", // TODO: is this right?
	}
	debian8OS := &grypeDB.OperatingSystem{
		Name:         "debian",
		ReleaseID:    "debian",
		MajorVersion: "8",
		Codename:     "jessie",
	}

	mariner2OS := &grypeDB.OperatingSystem{
		Name:         "mariner",
		ReleaseID:    "mariner",
		MajorVersion: "2",
		MinorVersion: "0", // TODO: is this right?
	}
	ol8OS := &grypeDB.OperatingSystem{
		Name:         "oraclelinux",
		ReleaseID:    "ol",
		MajorVersion: "8",
	}
	rhel8OS := &grypeDB.OperatingSystem{
		Name:         "redhat",
		ReleaseID:    "rhel",
		MajorVersion: "8",
	}
	tests := []struct {
		name     string
		provider string
		want     []transformers.RelatedEntries
	}{
		{
			name:     "test-fixtures/alpine-3.9.json",
			provider: "alpine",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2018-19967",
						Status:     "active",
						ProviderID: "alpine",
						Provider:   expectedProvider("alpine"),
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "CVE-2018-19967",
							References: []grypeDB.Reference{
								{
									URL: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: alpineOS,
							Package:         &grypeDB.Package{Ecosystem: "apk", Name: "xen"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "apk", Constraint: "< 4.11.1-r0"},
										Fix:     &grypeDB.Fix{Version: "4.11.1-r0", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/amzn.json",
			provider: "amazon",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "ALAS-2018-1106",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "ALAS-2018-1106",
							References: []grypeDB.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html",
								},
							},
							Aliases: []string{"CVE-2018-14648"},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &grypeDB.Package{
								Name:      "389-ds-base",
								Ecosystem: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &grypeDB.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &grypeDB.Package{
								Name:      "389-ds-base-debuginfo",
								Ecosystem: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &grypeDB.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &grypeDB.Package{
								Name:      "389-ds-base-devel",
								Ecosystem: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &grypeDB.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &grypeDB.Package{
								Name:      "389-ds-base-libs",
								Ecosystem: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &grypeDB.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &grypeDB.Package{
								Name:      "389-ds-base-snmp",
								Ecosystem: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &grypeDB.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/amazon-multiple-kernel-advisories.json",
			provider: "amazon",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "ALAS-2021-1704",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "ALAS-2021-1704",

							References: []grypeDB.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALAS-2021-1704.html",
								},
							},
							Aliases: []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 4.14.246-187.474.amzn2"},
										Fix:     &grypeDB.Fix{Version: "4.14.246-187.474.amzn2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 4.14.246-187.474.amzn2"},
										Fix:     &grypeDB.Fix{Version: "4.14.246-187.474.amzn2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "ALASKERNEL-5.4-2022-007",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "ALASKERNEL-5.4-2022-007",
							References: []grypeDB.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2022-007.html",
								},
							},
							Aliases: []string{"CVE-2021-3753", "CVE-2021-40490"},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: ">= 5.4, < 5.4.144-69.257.amzn2"},
										Fix:     &grypeDB.Fix{Version: "5.4.144-69.257.amzn2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: ">= 5.4, < 5.4.144-69.257.amzn2"},
										Fix:     &grypeDB.Fix{Version: "5.4.144-69.257.amzn2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "ALASKERNEL-5.10-2022-005",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "ALASKERNEL-5.10-2022-005",
							References: []grypeDB.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-005.html",
								},
							},
							Aliases: []string{"CVE-2021-3753", "CVE-2021-40490"},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: ">= 5.10, < 5.10.62-55.141.amzn2"},
										Fix:     &grypeDB.Fix{Version: "5.10.62-55.141.amzn2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: ">= 5.10, < 5.10.62-55.141.amzn2"},
										Fix:     &grypeDB.Fix{Version: "5.10.62-55.141.amzn2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/azure-linux-3.json",
			provider: "mariner",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2023-29403",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2023-29403",
							Description: "CVE-2023-29403 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29403",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "high",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: azure3OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "golang"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 0:1.20.7-1.azl3"},
										Fix:     &grypeDB.Fix{Version: "0:1.20.7-1.azl3", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/debian-8.json",
			provider: "debian",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2008-7220",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "CVE-2008-7220",
							References: []grypeDB.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2008-7220",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "high",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Ecosystem: "deb", Name: "asterisk"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "dpkg", Constraint: "< 1:1.6.2.0~rc3-1"},
										Fix:     &grypeDB.Fix{Version: "1:1.6.2.0~rc3-1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Ecosystem: "deb", Name: "auth2db"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "dpkg", Constraint: "< 0.2.5-2+dfsg-1"},
										Fix:     &grypeDB.Fix{Version: "0.2.5-2+dfsg-1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Ecosystem: "deb", Name: "exaile"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "dpkg", Constraint: "< 0.2.14+debian-2.2"},
										Fix:     &grypeDB.Fix{Version: "0.2.14+debian-2.2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Ecosystem: "deb", Name: "wordpress"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "dpkg", Constraint: ""},
										Fix:     &grypeDB.Fix{Version: "", State: grypeDB.NotFixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/debian-8-multiple-entries-for-same-package.json",
			provider: "debian",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2011-4623",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "CVE-2011-4623",
							References: []grypeDB.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2011-4623",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "low",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Ecosystem: "deb", Name: "rsyslog"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "dpkg", Constraint: "< 5.7.4-1"},
										Fix:     &grypeDB.Fix{Version: "5.7.4-1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2008-5618",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID: "CVE-2008-5618",
							References: []grypeDB.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2008-5618",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "low",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Ecosystem: "deb", Name: "rsyslog"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "dpkg", Constraint: "< 3.18.6-1"},
										Fix:     &grypeDB.Fix{Version: "3.18.6-1", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/mariner-20.json",
			provider: "mariner",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2021-37621",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2021-37621",
							Description: "CVE-2021-37621 affecting package exiv2 for versions less than 0.27.5-1. An upgraded version of the package is available that resolves this issue.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-37621",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},

					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "exiv2"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 0:0.27.5-1.cm2"},
										Fix:     &grypeDB.Fix{Version: "0:0.27.5-1.cm2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},

		{
			name:     "test-fixtures/mariner-range.json",
			provider: "mariner",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2023-29404",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2023-29404",
							Description: "CVE-2023-29404 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29404",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "critical",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "golang"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "> 0:1.19.0.cm2, < 0:1.20.7-1.cm2"},
										Fix:     &grypeDB.Fix{Version: "0:1.20.7-1.cm2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/ol-8.json",
			provider: "oracle",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:          "ELSA-2020-2550",
						ProviderID:    "oracle",
						Provider:      expectedProvider("oracle"),
						Status:        "active",
						PublishedDate: timeRef(time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)),
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:      "ELSA-2020-2550",
							Aliases: []string{"CVE-2020-13112"},
							References: []grypeDB.Reference{
								{
									URL: "http://linux.oracle.com/errata/ELSA-2020-2550.html",
								},
								{
									URL: "http://linux.oracle.com/cve/CVE-2020-13112.html",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "libexif"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 0:0.6.21-17.el8_2"},
										Fix:     &grypeDB.Fix{Version: "0:0.6.21-17.el8_2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "libexif-devel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: "< 0:0.6.21-17.el8_2"},
										Fix:     &grypeDB.Fix{Version: "0:0.6.21-17.el8_2", State: grypeDB.FixedStatus},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "libexif-dummy"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{Type: "rpm", Constraint: ""},
										Fix:     &grypeDB.Fix{State: grypeDB.NotFixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/ol-8-modules.json",
			provider: "oracle",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2020-14350",
						ProviderID: "oracle",
						Provider:   expectedProvider("oracle"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2020-14350",
							Description: "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []grypeDB.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-14350",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},

					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:10"),
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
										},
										Fix: &grypeDB.Fix{
											Version: "0:10.14-1.module+el8.2.0+7801+be0fed80",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:12"),
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
										},
										Fix: &grypeDB.Fix{
											Version: "0:12.5-1.module+el8.3.0+9042+664538f4",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:9.6"),
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
										},
										Fix: &grypeDB.Fix{
											Version: "0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/rhel-8.json",
			provider: "redhat",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2020-6819",
						ProviderID: "redhat",
						Provider:   expectedProvider("redhat"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2020-6819",
							Description: "A flaw was found in Mozilla Firefox. A race condition can occur while running the nsDocShell destructor causing a use-after-free memory issue. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
							References: []grypeDB.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-6819",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "critical",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Rank: 2,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "firefox"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:68.6.1-1.el8_1",
										},
										Fix: &grypeDB.Fix{
											Version: "0:68.6.1-1.el8_1",
											State:   grypeDB.FixedStatus,
											Detail: &grypeDB.FixDetail{
												References: []grypeDB.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:1341",
														Tags: []string{grypeDB.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "thunderbird"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:68.7.0-1.el8_1",
										},
										Fix: &grypeDB.Fix{
											Version: "0:68.7.0-1.el8_1",
											State:   grypeDB.FixedStatus,
											Detail: &grypeDB.FixDetail{
												References: []grypeDB.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:1495",
														Tags: []string{grypeDB.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/rhel-8-modules.json",
			provider: "redhat",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name:       "CVE-2020-14350",
						ProviderID: "redhat",
						Provider:   expectedProvider("redhat"),
						Status:     "active",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2020-14350",
							Description: "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []grypeDB.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-14350",
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Rank: 2,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:10"),
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
										},
										Fix: &grypeDB.Fix{
											Version: "0:10.14-1.module+el8.2.0+7801+be0fed80",
											State:   grypeDB.FixedStatus,
											Detail: &grypeDB.FixDetail{
												References: []grypeDB.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:3669",
														Tags: []string{grypeDB.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:12"),
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
										},
										Fix: &grypeDB.Fix{
											Version: "0:12.5-1.module+el8.3.0+9042+664538f4",
											State:   grypeDB.FixedStatus,
											Detail: &grypeDB.FixDetail{
												References: []grypeDB.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:5620",
														Tags: []string{grypeDB.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:9.6"),
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
										},
										Fix: &grypeDB.Fix{
											Version: "0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
											State:   grypeDB.FixedStatus,
											Detail: &grypeDB.FixDetail{
												References: []grypeDB.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:5619",
														Tags: []string{grypeDB.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vulns := loadFixture(t, test.name)

			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				entries, err := Transform(vuln, inputProviderState(test.provider))
				require.NoError(t, err)
				for _, entry := range entries {
					e, ok := entry.Data.(transformers.RelatedEntries)
					require.True(t, ok)
					actual = append(actual, e)
				}
			}

			if diff := cmp.Diff(test.want, actual); diff != "" {
				t.Errorf("data entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetOperatingSystem(t *testing.T) {
	tests := []struct {
		name      string
		osName    string
		osID      string
		osVersion string
		expected  *grypeDB.OperatingSystem
	}{
		{
			name:      "works with given args",
			osName:    "alpine",
			osID:      "alpine",
			osVersion: "3.10",
			expected: &grypeDB.OperatingSystem{
				Name:         "alpine",
				ReleaseID:    "alpine",
				MajorVersion: "3",
				MinorVersion: "10",
				LabelVersion: "",
				Codename:     "",
			},
		},
		{
			name:      "does codename lookup (debian)",
			osName:    "debian",
			osID:      "debian",
			osVersion: "11",
			expected: &grypeDB.OperatingSystem{
				Name:         "debian",
				ReleaseID:    "debian",
				MajorVersion: "11",
				MinorVersion: "",
				LabelVersion: "",
				Codename:     "bullseye",
			},
		},
		{
			name:      "does codename lookup (ubuntu)",
			osName:    "ubuntu",
			osID:      "ubuntu",
			osVersion: "22.04",
			expected: &grypeDB.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "22",
				MinorVersion: "04",
				LabelVersion: "",
				Codename:     "jammy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getOperatingSystem(tt.osName, tt.osID, tt.osVersion)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetOSInfo(t *testing.T) {
	tests := []struct {
		name       string
		group      string
		expectedOS string
		expectedID string
		expectedV  string
	}{
		{
			name:       "alpine 3.10",
			group:      "alpine:3.10",
			expectedOS: "alpine",
			expectedID: "alpine",
			expectedV:  "3.10",
		},
		{
			name:       "debian bullseye",
			group:      "debian:11",
			expectedOS: "debian",
			expectedID: "debian",
			expectedV:  "11",
		},
		{
			name:       "mariner version 1",
			group:      "mariner:1.0",
			expectedOS: "mariner",
			expectedID: "mariner",
			expectedV:  "1.0",
		},
		{
			name:       "mariner version 3 (azurelinux conversion)",
			group:      "mariner:3.0",
			expectedOS: "azurelinux",
			expectedID: "azurelinux",
			expectedV:  "3.0",
		},
		{
			name:       "ubuntu focal",
			group:      "ubuntu:20.04",
			expectedOS: "ubuntu",
			expectedID: "ubuntu",
			expectedV:  "20.04",
		},
		{
			name:       "oracle linux",
			group:      "ol:8",
			expectedOS: "oraclelinux", // normalize name
			expectedID: "ol",          // keep original ID
			expectedV:  "8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osName, id, version := getOSInfo(tt.group)
			require.Equal(t, tt.expectedOS, osName)
			require.Equal(t, tt.expectedID, id)
			require.Equal(t, tt.expectedV, version)
		})
	}
}

func affectedPkgSlice(a ...grypeDB.AffectedPackageHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.OSVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer tests.CloseFile(f)

	entries, err := unmarshal.OSVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func timeRef(ti time.Time) *time.Time {
	return &ti
}

func strRef(s string) *string {
	return &s
}
