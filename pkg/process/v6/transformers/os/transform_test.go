package os

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	testUtils "github.com/anchore/grype-db/pkg/process/internal/tests"
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

func expectedProvider(name string) grypeDB.Provider {
	return grypeDB.Provider{
		ID:           name,
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func TestTransform(t *testing.T) {

	amazonOS := &grypeDB.OperatingSystem{
		Name:         "amazon",
		MajorVersion: "2",
	}
	azure3OS := &grypeDB.OperatingSystem{
		Name:         "azurelinux",
		MajorVersion: "3",
		MinorVersion: "0", // TODO: is this right?
	}
	debian8OS := &grypeDB.OperatingSystem{
		Name:         "debian",
		MajorVersion: "8",
		Codename:     "jessie",
	}

	mariner2OS := &grypeDB.OperatingSystem{
		Name:         "mariner",
		MajorVersion: "2",
		MinorVersion: "0", // TODO: is this right?
	}
	ol8OS := &grypeDB.OperatingSystem{
		Name:         "oracle",
		MajorVersion: "8",
	}
	rhel8OS := &grypeDB.OperatingSystem{
		Name:         "redhat",
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
						Name: "CVE-2018-19967",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2018-19967",
							ProviderName: "alpine",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("alpine"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: &grypeDB.OperatingSystem{Name: "alpine", MajorVersion: "3", MinorVersion: "9"},
							Package:         &grypeDB.Package{Type: "apk", Name: "xen"},
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
						Name: "ALAS-2018-1106",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "ALAS-2018-1106",
							ProviderName: "amazon",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("amazon"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &grypeDB.Package{
								Name: "389-ds-base",
								Type: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-14648"},
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
								Name: "389-ds-base-debuginfo",
								Type: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-14648"},
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
								Name: "389-ds-base-devel",
								Type: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-14648"},
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
								Name: "389-ds-base-libs",
								Type: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-14648"},
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
								Name: "389-ds-base-snmp",
								Type: "rpm",
							},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-14648"},
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
						Name: "ALAS-2021-1704",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "ALAS-2021-1704",
							ProviderName: "amazon",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://alas.aws.amazon.com/AL2/ALAS-2021-1704.html",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("amazon"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "kernel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "kernel-headers"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
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
						Name: "ALASKERNEL-5.4-2022-007",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "ALASKERNEL-5.4-2022-007",
							ProviderName: "amazon",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2022-007.html",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("amazon"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "kernel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2021-3753", "CVE-2021-40490"},
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "kernel-headers"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2021-3753", "CVE-2021-40490"},
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
						Name: "ALASKERNEL-5.10-2022-005",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "ALASKERNEL-5.10-2022-005",
							ProviderName: "amazon",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-005.html",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("amazon"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "kernel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2021-3753", "CVE-2021-40490"},
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "kernel-headers"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2021-3753", "CVE-2021-40490"},
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
						Name: "CVE-2023-29403",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2023-29403",
							ProviderName: "mariner",
							Status:       "active",
							Description:  "CVE-2023-29403 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []grypeDB.Reference{
								{
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-29403",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("mariner"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: azure3OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "golang"},
							BlobValue: &grypeDB.AffectedPackageBlob{
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
						Name: "CVE-2008-7220",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2008-7220",
							ProviderName: "debian",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://security-tracker.debian.org/tracker/CVE-2008-7220",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("debian"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Type: "deb", Name: "asterisk"},
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
							Package:         &grypeDB.Package{Type: "deb", Name: "auth2db"},
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
							Package:         &grypeDB.Package{Type: "deb", Name: "exaile"},
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
							Package:         &grypeDB.Package{Type: "deb", Name: "wordpress"},
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
						Name: "CVE-2011-4623",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2011-4623",
							ProviderName:  "debian",
							Status:        "active",
							PublishedDate: &timeVal,
							References: []grypeDB.Reference{
								{
									URL:  "https://security-tracker.debian.org/tracker/CVE-2011-4623",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("debian"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Type: "deb", Name: "rsyslog"},
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
						Name: "CVE-2008-5618",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2008-5618",
							ProviderName: "debian",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://security-tracker.debian.org/tracker/CVE-2008-5618",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("debian"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &grypeDB.Package{Type: "deb", Name: "rsyslog"},
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
						Name: "CVE-2021-37621",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2021-37621",
							ProviderName: "mariner",
							Status:       "active",
							Description:  "CVE-2021-37621 affecting package exiv2 for versions less than 0.27.5-1. An upgraded version of the package is available that resolves this issue.",
							References: []grypeDB.Reference{
								{
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2021-37621",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("mariner"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "exiv2"},
							BlobValue: &grypeDB.AffectedPackageBlob{
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
						Name: "CVE-2023-29404",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2023-29404",
							ProviderName: "mariner",
							Status:       "active",
							Description:  "CVE-2023-29404 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []grypeDB.Reference{
								{
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-29404",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("mariner"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "golang"},
							BlobValue: &grypeDB.AffectedPackageBlob{
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
						Name: "ELSA-2020-2550",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "ELSA-2020-2550",
							ProviderName:  "oracle",
							Status:        "active",
							PublishedDate: timeRef(time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)),
							Aliases:       []string{"CVE-2020-13112"},
							References: []grypeDB.Reference{
								{
									URL:  "http://linux.oracle.com/errata/ELSA-2020-2550.html",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
								},
								{
									URL:  "http://linux.oracle.com/cve/CVE-2020-13112.html",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("oracle"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "libexif"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2020-13112"},
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "libexif-devel"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2020-13112"},
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "libexif-dummy"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2020-13112"},
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
						Name: "CVE-2020-14350",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2020-14350",
							Description:  "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							ProviderName: "oracle",
							Status:       "active",
							References: []grypeDB.Reference{
								{
									URL:  "https://access.redhat.com/security/cve/CVE-2020-14350",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
					Provider: expectedProvider("oracle"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: "postgresql:10",
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: "postgresql:12",
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: "postgresql:9.6",
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
						Name: "CVE-2020-6819",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2020-6819",
							ProviderName: "redhat",
							Status:       "active",
							Description:  "A flaw was found in Mozilla Firefox. A race condition can occur while running the nsDocShell destructor causing a use-after-free memory issue. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
							References: []grypeDB.Reference{
								{
									URL:  "https://access.redhat.com/security/cve/CVE-2020-6819",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
										Score:   8.8,
									},
									Rank: 2,
								},
							},
						},
					},
					Provider: expectedProvider("redhat"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "firefox"},
							BlobValue: &grypeDB.AffectedPackageBlob{
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "thunderbird"},
							BlobValue: &grypeDB.AffectedPackageBlob{
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
						Name: "CVE-2020-14350",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:           "CVE-2020-14350",
							ProviderName: "redhat",
							Status:       "active",
							Description:  "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []grypeDB.Reference{
								{
									URL:  "https://access.redhat.com/security/cve/CVE-2020-14350",
									Tags: []string{grypeDB.AdvisoryReferenceTag},
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
										Score:   7.1,
									},
									Rank: 2,
								},
							},
						},
					},
					Provider: expectedProvider("redhat"),
					Related: affectedPkgSlice(
						grypeDB.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &grypeDB.Package{Type: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: "postgresql:10",
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
														Tags: []string{grypeDB.AdvisoryReferenceTag},
														URL:  "https://access.redhat.com/errata/RHSA-2020:3669",
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: "postgresql:12",
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
														Tags: []string{grypeDB.AdvisoryReferenceTag},
														URL:  "https://access.redhat.com/errata/RHSA-2020:5620",
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
							Package:         &grypeDB.Package{Type: "rpm", Name: "postgresql"},
							BlobValue: &grypeDB.AffectedPackageBlob{
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									RpmModularity: "postgresql:9.6",
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
														Tags: []string{grypeDB.AdvisoryReferenceTag},
														URL:  "https://access.redhat.com/errata/RHSA-2020:5619",
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
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.OSVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func timeRef(ti time.Time) *time.Time {
	return &ti
}
