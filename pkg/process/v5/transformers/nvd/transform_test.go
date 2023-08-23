package nvd

import (
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testUtils "github.com/anchore/grype-db/pkg/process/tests"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/platformcpe"
)

func TestUnmarshalNVDVulnerabilitiesEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/unmarshal-test.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.NvdVulnerabilityEntries(f)
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestParseAllNVDVulnerabilityEntries(t *testing.T) {

	tests := []struct {
		name       string
		numEntries int
		fixture    string
		vulns      []grypeDB.Vulnerability
		metadata   grypeDB.VulnerabilityMetadata
	}{
		{
			name:       "AppVersionRange",
			numEntries: 1,
			fixture:    "test-fixtures/version-range.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2018-5487",
					PackageName: "oncommand_unified_manager",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint: ">= 7.2, <= 7.3",
					VersionFormat:     "unknown", // TODO: this should reference a format, yes? (not a string)
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:netapp:oncommand_unified_manager:*:*:*:*:*:*:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-5487",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2018-5487",
				Namespace:    "nvd:cpe",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "Critical",
				URLs:         []string{"https://security.netapp.com/advisory/ntap-20180523-0001/"},
				Description:  "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							7.5,
							10,
							6.4,
						),
						Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							9.8,
							3.9,
							5.9,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "App+OS",
			numEntries: 1,
			fixture:    "test-fixtures/single-package-multi-distro.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2018-1000222",
					PackageName:       "libgd",
					VersionConstraint: "= 2.2.5",
					VersionFormat:     "unknown", // TODO: this should reference a format, yes? (not a string)
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:libgd:libgd:2.2.5:*:*:*:*:*:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
				// TODO: Question: should this match also the OS's? (as in the vulnerable_cpes list)... this seems wrong!
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-1000222",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2018-1000222",
				Namespace:    "nvd:cpe",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs:         []string{"https://github.com/libgd/libgd/issues/447", "https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html", "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/", "https://security.gentoo.org/glsa/201903-18", "https://usn.ubuntu.com/3755-1/"},
				Description:  "Libgd version 2.2.5 contains a Double Free Vulnerability vulnerability in gdImageBmpPtr Function that can result in Remote Code Execution . This attack appear to be exploitable via Specially Crafted Jpeg Image can trigger double free. This vulnerability appears to have been fixed in after commit ac16bdf2d41724b5a65255d4c28fb0ec46bc42f5.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							6.8,
							8.6,
							6.4,
						),
						Vector:  "AV:N/AC:M/Au:N/C:P/I:P/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							8.8,
							2.8,
							5.9,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "AppCompoundVersionRange",
			numEntries: 1,
			fixture:    "test-fixtures/compound-pkg.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2018-10189",
					PackageName:       "mautic",
					VersionConstraint: ">= 1.0.0, <= 1.4.1 || >= 2.0.0, < 2.13.0",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:mautic:mautic:*:*:*:*:*:*:*:*"}, // note: entry was dedupicated
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-10189",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2018-10189",
				Namespace:    "nvd:cpe",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs:         []string{"https://github.com/mautic/mautic/releases/tag/2.13.0"},
				Description:  "An issue was discovered in Mautic 1.x and 2.x before 2.13.0. It is possible to systematically emulate tracking cookies per contact due to tracking the contact by their auto-incremented ID. Thus, a third party can manipulate the cookie value with +1 to systematically assume being tracked as each contact in Mautic. It is then possible to retrieve information about the contact through forms that have progressive profiling enabled.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							5,
							10,
							2.9,
						),
						Vector:  "AV:N/AC:L/Au:N/C:P/I:N/A:N",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							7.5,
							3.9,
							3.6,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			// we always keep the metadata even though there are no vulnerability entries for it
			name:       "InvalidCPE",
			numEntries: 1,
			fixture:    "test-fixtures/invalid_cpe.json",
			vulns:      nil,
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2015-8978",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2015-8978",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs: []string{
					"http://cpansearch.perl.org/src/PHRED/SOAP-Lite-1.20/Changes",
					"http://www.securityfocus.com/bid/94487",
				},
				Description: "In Soap Lite (aka the SOAP::Lite extension for Perl) 1.14 and earlier, an example attack consists of defining 10 or more XML entities, each defined as consisting of 10 of the previous entity, with the document consisting of a single instance of the largest entity, which expands to one billion copies of the first entity. The amount of computer memory used for handling an external SOAP call would likely exceed that available to the process parsing the XML.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							5,
							10,
							2.9,
						),
						Vector:  "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							7.5,
							3.9,
							3.6,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "With Platform CPE",
			numEntries: 1,
			fixture:    "test-fixtures/platform-cpe.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2022-26488",
					PackageName:       "active_iq_unified_manager",
					VersionConstraint: "",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
				{
					ID:                "CVE-2022-26488",
					PackageName:       "ontap_select_deploy_administration_utility",
					VersionConstraint: "",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
				{
					ID:          "CVE-2022-26488",
					PackageName: "python",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint: "<= 3.7.12 || >= 3.8.0, <= 3.8.12 || >= 3.9.0, <= 3.9.10 || >= 3.10.0, <= 3.10.2 || = 3.11.0-alpha1 || = 3.11.0-alpha2 || = 3.11.0-alpha3 || = 3.11.0-alpha4 || = 3.11.0-alpha5 || = 3.11.0-alpha6",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs: []string{
						"cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha1:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha2:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha3:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha4:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha5:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha6:*:*:*:*:*:*",
					},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2022-26488",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2022-26488",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs: []string{
					"https://mail.python.org/archives/list/security-announce@python.org/thread/657Z4XULWZNIY5FRP3OWXHYKUSIH6DMN/",
					"https://security.netapp.com/advisory/ntap-20220419-0005/",
				},
				Description: "In Python before 3.10.3 on Windows, local users can gain privileges because the search path is inadequately secured. The installer may allow a local attacker to add user-writable directories to the system search path. To exploit, an administrator must have installed Python for all users and enabled PATH entries. A non-administrative user can trigger a repair that incorrectly adds user-writable paths into PATH, enabling search-path hijacking of other users and system services. This affects Python (CPython) through 3.7.12, 3.8.x through 3.8.12, 3.9.x through 3.9.10, and 3.10.x through 3.10.2.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							4.4,
							3.4,
							6.4,
						),
						Vector:  "AV:L/AC:M/Au:N/C:P/I:P/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							7,
							1,
							5.9,
						),
						Vector:  "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
						Version: "3.1",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, f.Close())
			})

			entries, err := unmarshal.NvdVulnerabilityEntries(f)
			require.NoError(t, err)

			var vulns []grypeDB.Vulnerability
			for _, entry := range entries {
				dataEntries, err := Transform(entry.Cve)
				require.NoError(t, err)

				for _, entry := range dataEntries {
					switch vuln := entry.Data.(type) {
					case grypeDB.Vulnerability:
						vulns = append(vulns, vuln)
					case grypeDB.VulnerabilityMetadata:
						// check metadata
						if diff := deep.Equal(test.metadata, vuln); diff != nil {
							for _, d := range diff {
								t.Errorf("metadata diff: %+v", d)
							}
						}
					default:
						t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
					}
				}
			}

			if diff := cmp.Diff(test.vulns, vulns); diff != "" {
				t.Errorf("vulnerabilities do not match (-want +got):\n%s", diff)
			}
		})
	}
}
