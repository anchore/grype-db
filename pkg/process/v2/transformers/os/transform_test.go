package os

import (
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"os"
	"testing"

	testUtils "github.com/anchore/grype-db/pkg/process/tests"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v2"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalVulnerabilitiesEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/unmarshal-test.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.OSVulnerabilityEntries(f)
	require.NoError(t, err)

	require.Len(t, entries, 3)
}

func TestParseVulnerabilitiesEntry(t *testing.T) {
	tests := []struct {
		name        string
		numEntries  int
		fixture     string
		vulns       []grypeDB.Vulnerability
		metadata    grypeDB.VulnerabilityMetadata
		feed, group string
	}{
		{
			name:       "Amazon",
			numEntries: 1,
			fixture:    "test-fixtures/amzn.json",
			feed:       "vulnerabilities",
			group:      "amzn:2",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "ALAS-2018-1106",
					RecordSource:         "vulnerabilities:amzn:2",
					VersionConstraint:    "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2018-14648"},
					PackageName:          "389-ds-base",
					Namespace:            "amzn:2",
					FixedInVersion:       "1.3.8.4-15.amzn2.0.1",
				},
				{
					ID:                   "ALAS-2018-1106",
					RecordSource:         "vulnerabilities:amzn:2",
					VersionConstraint:    "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2018-14648"},
					PackageName:          "389-ds-base-debuginfo",
					Namespace:            "amzn:2",
					FixedInVersion:       "1.3.8.4-15.amzn2.0.1",
				},
				{
					ID:                   "ALAS-2018-1106",
					RecordSource:         "vulnerabilities:amzn:2",
					VersionConstraint:    "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2018-14648"},
					PackageName:          "389-ds-base-devel",
					Namespace:            "amzn:2",
					FixedInVersion:       "1.3.8.4-15.amzn2.0.1",
				},
				{
					ID:                   "ALAS-2018-1106",
					RecordSource:         "vulnerabilities:amzn:2",
					VersionConstraint:    "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2018-14648"},
					PackageName:          "389-ds-base-libs",
					Namespace:            "amzn:2",
					FixedInVersion:       "1.3.8.4-15.amzn2.0.1",
				},
				{
					ID:                   "ALAS-2018-1106",
					RecordSource:         "vulnerabilities:amzn:2",
					VersionConstraint:    "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2018-14648"},
					PackageName:          "389-ds-base-snmp",
					Namespace:            "amzn:2",
					FixedInVersion:       "1.3.8.4-15.amzn2.0.1",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "ALAS-2018-1106",
				RecordSource: "vulnerabilities:amzn:2",
				Severity:     "Medium",
				Links:        []string{"https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html"},
			},
		},
		{
			name:       "Debian",
			numEntries: 1,
			fixture:    "test-fixtures/debian-8.json",
			feed:       "vulnerabilities",
			group:      "debian:8",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2008-7220",
					RecordSource:         "vulnerabilities:debian:8",
					PackageName:          "asterisk",
					VersionConstraint:    "< 1:1.6.2.0~rc3-1",
					VersionFormat:        "dpkg", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "debian:8",
					FixedInVersion:       "1:1.6.2.0~rc3-1",
				},
				{
					ID:                   "CVE-2008-7220",
					RecordSource:         "vulnerabilities:debian:8",
					PackageName:          "auth2db",
					VersionConstraint:    "< 0.2.5-2+dfsg-1",
					VersionFormat:        "dpkg", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "debian:8",
					FixedInVersion:       "0.2.5-2+dfsg-1",
				},
				{
					ID:                   "CVE-2008-7220",
					RecordSource:         "vulnerabilities:debian:8",
					PackageName:          "exaile",
					VersionConstraint:    "< 0.2.14+debian-2.2",
					VersionFormat:        "dpkg", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "debian:8",
					FixedInVersion:       "0.2.14+debian-2.2",
				},
				{
					ID:                   "CVE-2008-7220",
					RecordSource:         "vulnerabilities:debian:8",
					PackageName:          "wordpress",
					VersionConstraint:    "",
					VersionFormat:        "dpkg", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "debian:8",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2008-7220",
				RecordSource: "vulnerabilities:debian:8",
				Severity:     "High",
				Links:        []string{"https://security-tracker.debian.org/tracker/CVE-2008-7220"},
				Description:  "",
				CvssV2: &grypeDB.Cvss{
					BaseScore: 7.5,
					Vector:    "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				},
			},
		},
		{
			name:       "RHEL",
			numEntries: 1,
			fixture:    "test-fixtures/rhel-8.json",
			feed:       "vulnerabilities",
			group:      "rhel:8",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2020-6819",
					RecordSource:         "vulnerabilities:rhel:8",
					PackageName:          "firefox",
					VersionConstraint:    "< 0:68.6.1-1.el8_1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "rhel:8",
					FixedInVersion:       "0:68.6.1-1.el8_1",
				},
				{
					ID:                   "CVE-2020-6819",
					RecordSource:         "vulnerabilities:rhel:8",
					PackageName:          "thunderbird",
					VersionConstraint:    "< 0:68.7.0-1.el8_1",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "rhel:8",
					FixedInVersion:       "0:68.7.0-1.el8_1",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-6819",
				RecordSource: "vulnerabilities:rhel:8",
				Severity:     "Critical",
				Links:        []string{"https://access.redhat.com/security/cve/CVE-2020-6819"},
				Description:  "A flaw was found in Mozilla Firefox. A race condition can occur while running the nsDocShell destructor causing a use-after-free memory issue. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
			},
		},
		{
			name:       "RHEL with modularity",
			numEntries: 1,
			fixture:    "test-fixtures/rhel-8-modules.json",
			feed:       "vulnerabilities",
			group:      "rhel:8",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2020-14350",
					RecordSource:         "vulnerabilities:rhel:8",
					PackageName:          "postgresql",
					VersionConstraint:    "< 0:12.5-1.module+el8.3.0+9042+664538f4",
					VersionFormat:        "rpm",
					ProxyVulnerabilities: []string{},
					Namespace:            "rhel:8",
					FixedInVersion:       "0:12.5-1.module+el8.3.0+9042+664538f4",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-14350",
				RecordSource: "vulnerabilities:rhel:8",
				Severity:     "Medium",
				Links:        []string{"https://access.redhat.com/security/cve/CVE-2020-14350"},
				Description:  "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
			},
		},
		{
			name:       "Alpine",
			numEntries: 1,
			fixture:    "test-fixtures/alpine-3.9.json",
			feed:       "vulnerabilities",
			group:      "alpine:3.9",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2018-19967",
					RecordSource:         "vulnerabilities:alpine:3.9",
					PackageName:          "xen",
					VersionConstraint:    "< 4.11.1-r0",
					VersionFormat:        "apk", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "alpine:3.9",
					FixedInVersion:       "4.11.1-r0",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-19967",
				RecordSource: "vulnerabilities:alpine:3.9",
				Severity:     "Medium",
				Links:        []string{"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967"},
				Description:  "",
				CvssV2: &grypeDB.Cvss{
					BaseScore:           4.9,
					ExploitabilityScore: 0,
					ImpactScore:         0,
					Vector:              "AV:L/AC:L/Au:N/C:N/I:N/A:C",
				},
			},
		},
		{
			name:       "Oracle",
			numEntries: 1,
			fixture:    "test-fixtures/ol-8.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "ELSA-2020-2550",
					RecordSource:         "vulnerabilities:ol:8",
					PackageName:          "libexif",
					VersionConstraint:    "< 0:0.6.21-17.el8_2",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2020-13112"},
					Namespace:            "ol:8",
					FixedInVersion:       "0:0.6.21-17.el8_2",
				},
				{
					ID:                   "ELSA-2020-2550",
					RecordSource:         "vulnerabilities:ol:8",
					PackageName:          "libexif-devel",
					VersionConstraint:    "< 0:0.6.21-17.el8_2",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2020-13112"},
					Namespace:            "ol:8",
					FixedInVersion:       "0:0.6.21-17.el8_2",
				},
				{
					ID:                   "ELSA-2020-2550",
					RecordSource:         "vulnerabilities:ol:8",
					PackageName:          "libexif-dummy",
					VersionConstraint:    "",
					VersionFormat:        "rpm", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{"CVE-2020-13112"},
					Namespace:            "ol:8",
					FixedInVersion:       "",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "ELSA-2020-2550",
				RecordSource: "vulnerabilities:ol:8",
				Severity:     "Medium",
				Links:        []string{"http://linux.oracle.com/errata/ELSA-2020-2550.html", "http://linux.oracle.com/cve/CVE-2020-13112.html"},
			},
		},
		{
			name:       "Oracle Linux 8 with modularity",
			numEntries: 1,
			fixture:    "test-fixtures/ol-8-modules.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2020-14350",
					RecordSource:         "vulnerabilities:ol:8",
					PackageName:          "postgresql",
					VersionConstraint:    "< 0:12.5-1.module+el8.3.0+9042+664538f4",
					VersionFormat:        "rpm",
					ProxyVulnerabilities: []string{},
					Namespace:            "ol:8",
					FixedInVersion:       "0:12.5-1.module+el8.3.0+9042+664538f4",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-14350",
				RecordSource: "vulnerabilities:ol:8",
				Severity:     "Medium",
				Links:        []string{"https://access.redhat.com/security/cve/CVE-2020-14350"},
				Description:  "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
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

			entries, err := unmarshal.OSVulnerabilityEntries(f)
			assert.NoError(t, err)
			assert.Len(t, entries, 1)

			entry := entries[0]

			dataEntries, err := Transform(entry)
			assert.NoError(t, err)

			var vulns []grypeDB.Vulnerability
			for _, entry := range dataEntries {
				switch vuln := entry.Data.(type) {
				case grypeDB.Vulnerability:
					vulns = append(vulns, vuln)
				case grypeDB.VulnerabilityMetadata:
					assert.Equal(t, test.metadata, vuln)
				default:
					t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
				}
			}

			if diff := cmp.Diff(test.vulns, vulns); diff != "" {
				t.Errorf("vulnerabilities do not match (-want +got):\n%s", diff)
			}

		})
	}

}

func TestParseVulnerabilitiesAllEntries(t *testing.T) {

	tests := []struct {
		name       string
		numEntries int
		fixture    string
		vulns      []grypeDB.Vulnerability
	}{
		{
			name:       "Debian",
			numEntries: 2,
			fixture:    "test-fixtures/debian-8-multiple-entries-for-same-package.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                   "CVE-2011-4623",
					RecordSource:         "vulnerabilities:debian:8",
					PackageName:          "rsyslog",
					VersionConstraint:    "< 5.7.4-1",
					VersionFormat:        "dpkg", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "debian:8",
					FixedInVersion:       "5.7.4-1",
				},
				{
					ID:                   "CVE-2008-5618",
					RecordSource:         "vulnerabilities:debian:8",
					PackageName:          "rsyslog",
					VersionConstraint:    "< 3.18.6-1",
					VersionFormat:        "dpkg", // TODO: this should reference a format, yes? (not a string)
					ProxyVulnerabilities: []string{},
					Namespace:            "debian:8",
					FixedInVersion:       "3.18.6-1",
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

			entries, err := unmarshal.OSVulnerabilityEntries(f)
			assert.NoError(t, err)
			assert.Len(t, entries, len(test.vulns))

			var vulns []grypeDB.Vulnerability
			for _, entry := range entries {
				assert.NoError(t, err)
				dataEntries, err := Transform(entry)
				assert.NoError(t, err)

				for _, entry := range dataEntries {
					switch vuln := entry.Data.(type) {
					case grypeDB.Vulnerability:
						vulns = append(vulns, vuln)
					case grypeDB.VulnerabilityMetadata:
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
