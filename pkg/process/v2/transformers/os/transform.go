package os

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v2/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v2"
)

const (
	// TODO: tech debt from a previous design
	feed = "vulnerabilities"
)

func Transform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	group := vulnerability.Vulnerability.NamespaceName

	var allVulns []grypeDB.Vulnerability

	recordSource := grypeDB.RecordSource(feed, group)
	vulnerability.Vulnerability.FixedIn = vulnerability.Vulnerability.FixedIn.FilterToHighestModularity()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespace combo) while merging
	// constraint ranges as they are found.
	for _, advisory := range vulnerability.Vulnerability.FixedIn {
		constraint, err := enforceConstraint(advisory.Version, advisory.VersionFormat)
		if err != nil {
			return nil, err
		}

		// create vulnerability entry
		vuln := grypeDB.Vulnerability{
			ID:                   vulnerability.Vulnerability.Name,
			RecordSource:         recordSource,
			VersionConstraint:    constraint,
			VersionFormat:        advisory.VersionFormat,
			PackageName:          advisory.Name,
			Namespace:            advisory.NamespaceName,
			ProxyVulnerabilities: []string{},
			FixedInVersion:       common.CleanFixedInVersion(advisory.Version),
		}

		// associate related vulnerabilities
		// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
		for _, ref := range vulnerability.Vulnerability.Metadata.CVE {
			vuln.ProxyVulnerabilities = append(vuln.ProxyVulnerabilities, ref.Name)
		}

		allVulns = append(allVulns, vuln)
	}

	var cvssV2 *grypeDB.Cvss
	if vulnerability.Vulnerability.Metadata.NVD.CVSSv2.Vectors != "" {
		cvssV2 = &grypeDB.Cvss{
			BaseScore:           vulnerability.Vulnerability.Metadata.NVD.CVSSv2.Score,
			ExploitabilityScore: 0,
			ImpactScore:         0,
			Vector:              vulnerability.Vulnerability.Metadata.NVD.CVSSv2.Vectors,
		}
	}

	// find all URLs related to the vulnerability
	links := []string{vulnerability.Vulnerability.Link}
	if vulnerability.Vulnerability.Metadata.CVE != nil {
		for _, cve := range vulnerability.Vulnerability.Metadata.CVE {
			if cve.Link != "" {
				links = append(links, cve.Link)
			}
		}
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.Vulnerability.Name,
		RecordSource: recordSource,
		Severity:     vulnerability.Vulnerability.Severity,
		Links:        links,
		Description:  vulnerability.Vulnerability.Description,
		CvssV2:       cvssV2,
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func enforceConstraint(constraint, format string) (string, error) {
	constraint = common.CleanConstraint(constraint)
	if len(constraint) == 0 {
		return "", nil
	}
	switch strings.ToLower(format) {
	case "dpkg", "rpm", "apk":
		// the passed constraint is a fixed version
		return fmt.Sprintf("< %s", constraint), nil
	case "semver":
		return common.EnforceSemVerConstraint(constraint), nil
	}
	return "", fmt.Errorf("unable to enforce constraint='%s' format='%s'", constraint, format)
}
