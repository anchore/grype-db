package nvd

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

	tests := []struct {
		name     string
		config   Config
		provider string
		want     []transformers.RelatedEntries
	}{
		{
			name:     "test-fixtures/version-range.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2018-5487",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2018-5487",
							ProviderName:  "nvd",
							Assigner:      []string{"security-alert@netapp.com"},
							Description:   "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
							ModifiedDate:  timeRef(time.Date(2018, 7, 5, 13, 52, 30, 627000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2018, 5, 24, 14, 29, 0, 390000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2018-5487",
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20180523-0001/",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										Version: "3.0",
										Score:   9.8,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
										Version: "2.0",
										Score:   7.5,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-5487"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 7.2, <= 7.3",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "netapp",
								Product: "oncommand_unified_manager",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/single-package-multi-distro.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2018-1000222",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2018-1000222",
							ProviderName:  "nvd",
							Assigner:      []string{"cve@mitre.org"},
							Description:   "Libgd version 2.2.5 contains a Double Free Vulnerability vulnerability in gdImageBmpPtr Function that can result in Remote Code Execution . This attack appear to be exploitable via Specially Crafted Jpeg Image can trigger double free. This vulnerability appears to have been fixed in after commit ac16bdf2d41724b5a65255d4c28fb0ec46bc42f5.",
							ModifiedDate:  timeRef(time.Date(2020, 3, 31, 2, 15, 12, 667000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2018, 8, 20, 20, 29, 1, 347000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2018-1000222",
								},
								{
									URL:  "https://github.com/libgd/libgd/issues/447",
									Tags: []string{"issue-tracking", "third-party-advisory"},
								},
								{
									URL:  "https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL: "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/",
								},
								{
									URL:  "https://security.gentoo.org/glsa/201903-18",
									Tags: []string{"third-party-advisory"},
								},
								{
									URL:  "https://usn.ubuntu.com/3755-1/",
									Tags: []string{"mitigation", "third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.0",
										Score:   8.8,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:M/Au:N/C:P/I:P/A:P",
										Version: "2.0",
										Score:   6.8,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-1000222"},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: "= 2.2.5",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "libgd",
								Product: "libgd",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/compound-pkg.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2018-10189",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2018-10189",
							ProviderName:  "nvd",
							Assigner:      []string{"cve@mitre.org"},
							Description:   "An issue was discovered in Mautic 1.x and 2.x before 2.13.0. It is possible to systematically emulate tracking cookies per contact due to tracking the contact by their auto-incremented ID. Thus, a third party can manipulate the cookie value with +1 to systematically assume being tracked as each contact in Mautic. It is then possible to retrieve information about the contact through forms that have progressive profiling enabled.",
							ModifiedDate:  timeRef(time.Date(2018, 5, 23, 14, 41, 49, 73000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2018, 4, 17, 20, 29, 0, 410000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2018-10189",
								},
								{
									URL:  "https://github.com/mautic/mautic/releases/tag/2.13.0",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.0",
										Score:   7.5,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:P/I:N/A:N",
										Version: "2.0",
										Score:   5.0,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2018-10189"},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 1.0.0, <= 1.4.1",
										},
										// since the top range operator is <= we cannot infer a fix
									},
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 2.0.0, < 2.13.0",
										},
										Fix: &grypeDB.Fix{
											Version: "2.13.0",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "mautic",
								Product: "mautic",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/invalid_cpe.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2015-8978",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2015-8978",
							ProviderName:  "nvd",
							Assigner:      []string{"cve@mitre.org"},
							Description:   "In Soap Lite (aka the SOAP::Lite extension for Perl) 1.14 and earlier, an example attack consists of defining 10 or more XML entities, each defined as consisting of 10 of the previous entity, with the document consisting of a single instance of the largest entity, which expands to one billion copies of the first entity. The amount of computer memory used for handling an external SOAP call would likely exceed that available to the process parsing the XML.",
							ModifiedDate:  timeRef(time.Date(2016, 11, 28, 19, 50, 59, 600000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2016, 11, 22, 17, 59, 0, 180000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2015-8978",
								},
								{
									URL:  "http://cpansearch.perl.org/src/PHRED/SOAP-Lite-1.20/Changes",
									Tags: []string{"vendor-advisory"},
								},
								{
									URL:  "http://www.securityfocus.com/bid/94487",
									Tags: nil,
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										Version: "3.0",
										Score:   7.5,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:N/I:N/A:P",
										Version: "2.0",
										Score:   5.0,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related:  nil, // when we can't parse the CPE we should not add any affected blobs (but we do add the vuln blob)
				},
			},
		},
		{
			name:     "test-fixtures/platform-cpe.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2022-26488",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2022-26488",
							ProviderName:  "nvd",
							Assigner:      []string{"cve@mitre.org"},
							Description:   "In Python before 3.10.3 on Windows, local users can gain privileges because the search path is inadequately secured. The installer may allow a local attacker to add user-writable directories to the system search path. To exploit, an administrator must have installed Python for all users and enabled PATH entries. A non-administrative user can trigger a repair that incorrectly adds user-writable paths into PATH, enabling search-path hijacking of other users and system services. This affects Python (CPython) through 3.7.12, 3.8.x through 3.8.12, 3.9.x through 3.9.10, and 3.10.x through 3.10.2.",
							ModifiedDate:  timeRef(time.Date(2022, 9, 3, 3, 34, 19, 933000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2022, 3, 10, 17, 47, 45, 383000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2022-26488",
								},
								{
									URL:  "https://mail.python.org/archives/list/security-announce@python.org/thread/657Z4XULWZNIY5FRP3OWXHYKUSIH6DMN/",
									Tags: []string{"patch", "vendor-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20220419-0005/",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
										Version: "3.1",
										Score:   7.0,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:L/AC:M/Au:N/C:P/I:P/A:P",
										Version: "2.0",
										Score:   4.4,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2022-26488"},
							},
							CPE: &grypeDB.Cpe{
								Type:           "a",
								Vendor:         "netapp",
								Product:        "active_iq_unified_manager",
								TargetSoftware: "windows",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2022-26488"},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "netapp",
								Product: "ontap_select_deploy_administration_utility",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2022-26488"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.AffectedRange{
									{Version: grypeDB.AffectedVersion{Constraint: "<= 3.7.12"}},
									{Version: grypeDB.AffectedVersion{Constraint: ">= 3.8.0, <= 3.8.12"}},
									{Version: grypeDB.AffectedVersion{Constraint: ">= 3.9.0, <= 3.9.10"}},
									{Version: grypeDB.AffectedVersion{Constraint: ">= 3.10.0, <= 3.10.2"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha1"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha2"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha3"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha4"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha4"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha5"}},
									{Version: grypeDB.AffectedVersion{Constraint: "= 3.11.0-alpha6"}},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "python",
								Product: "python",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/cve-2022-0543.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2022-0543",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2022-0543",
							ProviderName:  "nvd",
							Assigner:      []string{"security@debian.org"},
							Description:   "It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.",
							ModifiedDate:  timeRef(time.Date(2023, 9, 29, 15, 55, 24, 533000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2022, 2, 18, 20, 15, 17, 583000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
								},
								{
									URL:  "http://packetstormsecurity.com/files/166885/Redis-Lua-Sandbox-Escape.html",
									Tags: []string{"exploit", "third-party-advisory", "vdb-entry"},
								},
								{
									URL:  "https://bugs.debian.org/1005787",
									Tags: []string{"issue-tracking", "patch", "third-party-advisory"},
								},
								{
									URL:  "https://lists.debian.org/debian-security-announce/2022/msg00048.html",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20220331-0004/",
									Tags: []string{"third-party-advisory"},
								},
								{
									URL:  "https://www.debian.org/security/2022/dsa-5081",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL:  "https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
										Version: "3.1",
										Score:   10.0,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:C/I:C/A:C",
										Version: "2.0",
										Score:   10.0,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2022-0543"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{
										"cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
										"cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
										"cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
										"cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
										"cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "redis",
								Product: "redis",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/cve-2020-10729.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2020-10729",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2020-10729",
							ProviderName:  "nvd",
							Assigner:      []string{"secalert@redhat.com"},
							Description:   "A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the same length generate the equal value as the template caching action for the same file since no re-evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at once for the file. This flaw affects Ansible Engine versions before 2.9.6.",
							ModifiedDate:  timeRef(time.Date(2021, 12, 10, 19, 57, 6, 357000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2021, 5, 27, 19, 15, 7, 880000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2020-10729",
								},
								{
									URL:  "https://bugzilla.redhat.com/show_bug.cgi?id=1831089",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://github.com/ansible/ansible/issues/34144",
									Tags: []string{"exploit", "issue-tracking", "third-party-advisory"},
								},
								{
									URL:  "https://www.debian.org/security/2021/dsa-4950",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.1",
										Score:   5.5,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:L/AC:L/Au:N/C:P/I:N/A:N",
										Version: "2.0",
										Score:   2.1,
									},
									Source: "nvd@nist.gov",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2020-10729"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{
										"cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*",
										"cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
									},
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: "< 2.9.6",
										},
										Fix: &grypeDB.Fix{
											Version: "2.9.6",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "redhat",
								Product: "ansible_engine",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/multiple-platforms-with-application-cpe.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2023-38733",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2023-38733",
							ProviderName:  "nvd",
							Assigner:      []string{"psirt@us.ibm.com"},
							Description:   "IBM Robotic Process Automation 21.0.0 through 21.0.7.1 and 23.0.0 through 23.0.1 server could allow an authenticated user to view sensitive information from installation logs.  IBM X-Force Id:  262293.",
							ModifiedDate:  timeRef(time.Date(2023, 8, 26, 2, 25, 42, 957000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2023, 8, 22, 22, 15, 8, 460000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-38733",
								},
								{
									URL:  "https://exchange.xforce.ibmcloud.com/vulnerabilities/262293",
									Tags: []string{"vdb-entry", "vendor-advisory"},
								},
								{
									URL:  "https://www.ibm.com/support/pages/node/7028223",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
										Version: "3.1",
										Score:   4.3,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
										Version: "3.1",
										Score:   4.3,
									},
									Source: "psirt@us.ibm.com",
									Rank:   2,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2023-38733"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{
										"cpe:2.3:a:redhat:openshift:-:*:*:*:*:*:*:*",
										"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
									},
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 21.0.0, <= 21.0.7.3",
										},
									},
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 23.0.0, <= 23.0.3",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "ibm",
								Product: "robotic_process_automation",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/CVE-2023-45283-platform-cpe-first.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2023-45283",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2023-45283",
							ProviderName:  "nvd",
							Assigner:      []string{"security@golang.org"},
							Description:   "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
							ModifiedDate:  timeRef(time.Date(2023, 12, 14, 10, 15, 7, 947000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2023, 11, 9, 17, 15, 8, 757000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
								},
								{
									URL:  "http://www.openwall.com/lists/oss-security/2023/12/05/2",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/cl/540277",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/cl/541175",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/issue/63713",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/issue/64028",
									Tags: nil,
								},
								{
									URL:  "https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
									Tags: []string{"issue-tracking", "mailing-list", "vendor-advisory"},
								},
								{
									URL:  "https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
									Tags: nil,
								},
								{
									URL:  "https://pkg.go.dev/vuln/GO-2023-2185",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20231214-0008/",
									Tags: nil,
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.1",
										Score:   7.5,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2023-45283"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: "< 1.20.11",
										},
										Fix: &grypeDB.Fix{
											Version: "1.20.11",
											State:   grypeDB.FixedStatus,
										},
									},
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 1.21.0-0, < 1.21.4",
										},
										Fix: &grypeDB.Fix{
											Version: "1.21.4",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "golang",
								Product: "go",
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/CVE-2023-45283-platform-cpe-last.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: grypeDB.VulnerabilityHandle{
						Name: "CVE-2023-45283",
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:            "CVE-2023-45283",
							ProviderName:  "nvd",
							Assigner:      []string{"security@golang.org"},
							Description:   "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
							ModifiedDate:  timeRef(time.Date(2023, 12, 14, 10, 15, 7, 947000000, time.UTC)),
							PublishedDate: timeRef(time.Date(2023, 11, 9, 17, 15, 8, 757000000, time.UTC)),
							Status:        grypeDB.VulnerabilityActive,
							References: []grypeDB.Reference{
								{
									Tags: []string{grypeDB.AdvisoryReferenceTag},
									URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
								},
								{
									URL:  "http://www.openwall.com/lists/oss-security/2023/12/05/2",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/cl/540277",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/cl/541175",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/issue/63713",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/issue/64028",
									Tags: nil,
								},
								{
									URL:  "https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
									Tags: []string{"issue-tracking", "mailing-list", "vendor-advisory"},
								},
								{
									URL:  "https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
									Tags: nil,
								},
								{
									URL:  "https://pkg.go.dev/vuln/GO-2023-2185",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20231214-0008/",
									Tags: nil,
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.1",
										Score:   7.5,
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Provider: expectedProvider("nvd"),
					Related: affectedPkgSlice(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.AffectedPackageBlob{
								CVEs: []string{"CVE-2023-45283"},
								Qualifiers: &grypeDB.AffectedPackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.AffectedRange{
									{
										Version: grypeDB.AffectedVersion{
											Constraint: "< 1.20.11",
										},
										Fix: &grypeDB.Fix{
											Version: "1.20.11",
											State:   grypeDB.FixedStatus,
										},
									},
									{
										Version: grypeDB.AffectedVersion{
											Constraint: ">= 1.21.0-0, < 1.21.4",
										},
										Fix: &grypeDB.Fix{
											Version: "1.21.4",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Type:    "a",
								Vendor:  "golang",
								Product: "go",
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
				if test.config == (Config{}) {
					test.config = defaultConfig()
				}
				entries, err := Transformer(test.config)(vuln, inputProviderState(test.provider))
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

func affectedPkgSlice(a ...grypeDB.AffectedCPEHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.NVDVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer tests.CloseFile(f)

	entries, err := unmarshal.NvdVulnerabilityEntries(f)
	require.NoError(t, err)

	var vulns []unmarshal.NVDVulnerability
	for _, entry := range entries {
		vulns = append(vulns, entry.Cve)
	}

	return vulns
}

func timeRef(ti time.Time) *time.Time {
	return &ti
}