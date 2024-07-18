package nvd

import (
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testUtils "github.com/anchore/grype-db/pkg/process/internal/tests"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v1"
)

const recordSource = "nvdv2:cves"

func TestUnmarshalVulnerabilitiesEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/unmarshal-test.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.NvdVulnerabilityEntries(f)
	require.NoError(t, err)

	assert.Len(t, entries, 1)
}

func TestParseVulnerabilitiesAllEntries(t *testing.T) {
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
					ID:                   "CVE-2018-5487",
					RecordSource:         recordSource,
					PackageName:          "oncommand_unified_manager",
					VersionConstraint:    ">= 7.2, <= 7.3",
					VersionFormat:        "unknown", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "nvd",
					CPEs:                 []string{"cpe:2.3:a:netapp:oncommand_unified_manager:*:*:*:*:*:*:*:*"},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-5487",
				RecordSource: recordSource,
				Severity:     "Critical",
				Links:        []string{"https://security.netapp.com/advisory/ntap-20180523-0001/"},
				Description:  "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
				CvssV2: &grypeDB.Cvss{
					BaseScore:           7.5,
					ExploitabilityScore: 10,
					ImpactScore:         6.4,
					Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				},
				CvssV3: &grypeDB.Cvss{
					BaseScore:           9.8,
					ExploitabilityScore: 3.9,
					ImpactScore:         5.9,
					Vector:              "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
		},
		{
			name:       "App+OS",
			numEntries: 1,
			fixture:    "test-fixtures/single-package-multi-distro.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2018-1000222",
					RecordSource:         recordSource,
					PackageName:          "libgd",
					VersionConstraint:    "= 2.2.5",
					VersionFormat:        "unknown", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "nvd",
					CPEs:                 []string{"cpe:2.3:a:libgd:libgd:2.2.5:*:*:*:*:*:*:*"},
				},
				// TODO: Question: should this match also the OS's? (as in the vulnerable_cpes list)... this seems wrong!
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-1000222",
				RecordSource: recordSource,
				Severity:     "High",
				Links:        []string{"https://github.com/libgd/libgd/issues/447", "https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html", "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/", "https://security.gentoo.org/glsa/201903-18", "https://usn.ubuntu.com/3755-1/"},
				Description:  "Libgd version 2.2.5 contains a Double Free Vulnerability vulnerability in gdImageBmpPtr Function that can result in Remote Code Execution . This attack appear to be exploitable via Specially Crafted Jpeg Image can trigger double free. This vulnerability appears to have been fixed in after commit ac16bdf2d41724b5a65255d4c28fb0ec46bc42f5.",
				CvssV2: &grypeDB.Cvss{
					BaseScore:           6.8,
					ExploitabilityScore: 8.6,
					ImpactScore:         6.4,
					Vector:              "AV:N/AC:M/Au:N/C:P/I:P/A:P",
				},
				CvssV3: &grypeDB.Cvss{
					BaseScore:           8.8,
					ExploitabilityScore: 2.8,
					ImpactScore:         5.9,
					Vector:              "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
				},
			},
		},
		{
			name:       "AppCompoundVersionRange",
			numEntries: 1,
			fixture:    "test-fixtures/compound-pkg.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2018-10189",
					RecordSource:         recordSource,
					PackageName:          "mautic",
					VersionConstraint:    ">= 1.0.0, <= 1.4.1 || >= 2.0.0, < 2.13.0",
					VersionFormat:        "unknown", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "nvd",
					CPEs:                 []string{"cpe:2.3:a:mautic:mautic:*:*:*:*:*:*:*:*"}, // note: entry was dedupicated
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-10189",
				RecordSource: recordSource,
				Severity:     "High",
				Links:        []string{"https://github.com/mautic/mautic/releases/tag/2.13.0"},
				Description:  "An issue was discovered in Mautic 1.x and 2.x before 2.13.0. It is possible to systematically emulate tracking cookies per contact due to tracking the contact by their auto-incremented ID. Thus, a third party can manipulate the cookie value with +1 to systematically assume being tracked as each contact in Mautic. It is then possible to retrieve information about the contact through forms that have progressive profiling enabled.",
				CvssV2: &grypeDB.Cvss{
					BaseScore:           5,
					ExploitabilityScore: 10,
					ImpactScore:         2.9,
					Vector:              "AV:N/AC:L/Au:N/C:P/I:N/A:N",
				},
				CvssV3: &grypeDB.Cvss{
					BaseScore:           7.5,
					ExploitabilityScore: 3.9,
					ImpactScore:         3.6,
					Vector:              "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				},
			},
		},
		{
			name:       "InvalidCPE",
			numEntries: 1,
			fixture:    "test-fixtures/invalid_cpe.json",
			vulns:      []grypeDB.Vulnerability{},
			metadata:   grypeDB.VulnerabilityMetadata{},
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
			assert.NoError(t, err)

			var vulns []grypeDB.Vulnerability
			for _, entry := range entries {
				dataEntries, err := Transform(entry.Cve)
				assert.NoError(t, err)

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

			assert.ElementsMatch(t, test.vulns, vulns)
		})
	}
}
