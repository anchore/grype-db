package os

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/common"
	"github.com/anchore/grype-db/pkg/process/v1/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v1"
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
		// create vulnerability entry
		vuln := grypeDB.Vulnerability{
			ID:                   vulnerability.Vulnerability.Name,
			RecordSource:         recordSource,
			VersionConstraint:    enforceConstraint(advisory.Version, advisory.VersionFormat, vulnerability.Vulnerability.Name),
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

func deriveConstraintFromFix(fixVersion, vulnerabilityID string) string {
	constraint := fmt.Sprintf("< %s", fixVersion)

	if strings.HasPrefix(vulnerabilityID, "ALASKERNEL-") {
		// Amazon advisories of the form ALASKERNEL-5.4-2023-048 should be interpreted as only applying to
		// the 5.4.x kernel line since Amazon issue a separate advisory per affected line, thus the constraint
		// should be >= 5.4, < {fix version}.  In the future the vunnel schema for OS vulns should be enhanced
		// to emit actual constraints rather than fixed-in entries (tracked in https://github.com/anchore/vunnel/issues/266)
		// at which point this workaround in grype-db can be removed.

		components := strings.Split(vulnerabilityID, "-")

		if len(components) == 4 {
			base := components[1]
			constraint = fmt.Sprintf(">= %s, < %s", base, fixVersion)
		}
	}

	return constraint
}

func enforceConstraint(constraint, format, vulnerabilityID string) string {
	constraint = common.CleanConstraint(constraint)
	if len(constraint) == 0 {
		return ""
	}
	switch strings.ToLower(format) {
	case "semver":
		return common.EnforceSemVerConstraint(constraint)
	default:
		// the passed constraint is a fixed version
		return deriveConstraintFromFix(constraint, vulnerabilityID)
	}
}
