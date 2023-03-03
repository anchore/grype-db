package os

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v5/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/grype/distro"
)

func buildGrypeNamespace(group string) (namespace.Namespace, error) {
	feedGroupComponents := strings.Split(group, ":")

	if len(feedGroupComponents) < 2 {
		return nil, fmt.Errorf("unable to determine grype namespace for enterprise namespace=%s", group)
	}

	// Currently known enterprise feed groups are expected to be of the form {distroID}:{version}
	feedGroupDistroID := feedGroupComponents[0]
	d, ok := distro.IDMapping[feedGroupDistroID]
	if !ok {
		return nil, fmt.Errorf("unable to determine grype namespace for enterprise namespace=%s", group)
	}

	providerName := d.String()

	switch d {
	case distro.OracleLinux:
		providerName = "oracle"
	case distro.AmazonLinux:
		providerName = "amazon"
	}

	ns, err := namespace.FromString(fmt.Sprintf("%s:distro:%s:%s", providerName, d.String(), feedGroupComponents[1]))

	if err != nil {
		return nil, err
	}

	return ns, nil
}

func Transform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	var allVulns []grypeDB.Vulnerability

	// TODO: stop capturing record source in the vulnerability metadata record (now that feed groups are not real)
	recordSource := fmt.Sprintf("vulnerabilities:%s", vulnerability.Vulnerability.NamespaceName)

	grypeNamespace, err := buildGrypeNamespace(vulnerability.Vulnerability.NamespaceName)
	if err != nil {
		return nil, err
	}

	entryNamespace := grypeNamespace.String()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespace combo) while merging
	// constraint ranges as they are found.
	for idx, fixedInEntry := range vulnerability.Vulnerability.FixedIn {
		constraint, err := enforceConstraint(fixedInEntry.Version, fixedInEntry.VersionFormat)
		if err != nil {
			return nil, err
		}

		var qualifiers []qualifier.Qualifier

		if fixedInEntry.Module != nil {
			qualifiers = []qualifier.Qualifier{rpmmodularity.Qualifier{
				Kind:   "rpm-modularity",
				Module: *fixedInEntry.Module,
			}}
		}

		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                     vulnerability.Vulnerability.Name,
			PackageQualifiers:      qualifiers,
			VersionConstraint:      constraint,
			VersionFormat:          fixedInEntry.VersionFormat,
			PackageName:            grypeNamespace.Resolver().Normalize(fixedInEntry.Name),
			Namespace:              entryNamespace,
			RelatedVulnerabilities: getRelatedVulnerabilities(vulnerability),
			Fix:                    getFix(vulnerability, idx),
			Advisories:             getAdvisories(vulnerability, idx),
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.Vulnerability.Name,
		Namespace:    entryNamespace,
		DataSource:   vulnerability.Vulnerability.Link,
		RecordSource: recordSource,
		Severity:     vulnerability.Vulnerability.Severity,
		URLs:         getLinks(vulnerability),
		Description:  vulnerability.Vulnerability.Description,
		Cvss:         getCvss(vulnerability),
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getLinks(entry unmarshal.OSVulnerability) []string {
	// find all URLs related to the vulnerability
	links := []string{entry.Vulnerability.Link}
	if entry.Vulnerability.Metadata.CVE != nil {
		for _, cve := range entry.Vulnerability.Metadata.CVE {
			if cve.Link != "" {
				links = append(links, cve.Link)
			}
		}
	}
	return links
}

func getCvss(entry unmarshal.OSVulnerability) (cvss []grypeDB.Cvss) {
	for _, vendorCvss := range entry.Vulnerability.CVSS {
		cvss = append(cvss, grypeDB.Cvss{
			Version: vendorCvss.Version,
			Vector:  vendorCvss.VectorString,
			Metrics: grypeDB.NewCvssMetrics(
				vendorCvss.BaseMetrics.BaseScore,
				vendorCvss.BaseMetrics.ExploitabilityScore,
				vendorCvss.BaseMetrics.ImpactScore,
			),
			VendorMetadata: transformers.VendorBaseMetrics{
				BaseSeverity: vendorCvss.BaseMetrics.BaseSeverity,
				Status:       vendorCvss.Status,
			},
		})
	}
	return cvss
}

func getAdvisories(entry unmarshal.OSVulnerability, idx int) (advisories []grypeDB.Advisory) {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	for _, advisory := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		advisories = append(advisories, grypeDB.Advisory{
			ID:   advisory.ID,
			Link: advisory.Link,
		})
	}
	return advisories
}

func getFix(entry unmarshal.OSVulnerability, idx int) grypeDB.Fix {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	var fixedInVersions []string
	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Version)
	if fixedInVersion != "" {
		fixedInVersions = append(fixedInVersions, fixedInVersion)
	}

	fixState := grypeDB.NotFixedState
	if len(fixedInVersions) > 0 {
		fixState = grypeDB.FixedState
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = grypeDB.WontFixState
	}

	return grypeDB.Fix{
		Versions: fixedInVersions,
		State:    fixState,
	}
}

func getRelatedVulnerabilities(entry unmarshal.OSVulnerability) (vulns []grypeDB.VulnerabilityReference) {
	// associate related vulnerabilities from the NVD namespace
	if strings.HasPrefix(entry.Vulnerability.Name, "CVE") {
		vulns = append(vulns, grypeDB.VulnerabilityReference{
			ID:        entry.Vulnerability.Name,
			Namespace: "nvd:cpe",
		})
	}

	// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
	for _, ref := range entry.Vulnerability.Metadata.CVE {
		vulns = append(vulns, grypeDB.VulnerabilityReference{
			ID:        ref.Name,
			Namespace: "nvd:cpe",
		})
	}
	return vulns
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
