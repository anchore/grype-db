package nvd

import (
	"strings"

	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"

	"github.com/anchore/grype-db/internal"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v2/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v2"
)

const (
	// TODO: tech debt from a previous design
	feed  = "nvdv2"
	group = "nvdv2:cves"
)

func Transform(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	var allVulns []grypeDB.Vulnerability

	recordSource := grypeDB.RecordSource(feed, group)

	uniquePkgs := findUniquePkgs(vulnerability.Configurations...)

	// extract all links
	var links []string
	for _, externalRefs := range vulnerability.References {
		// TODO: should we capture other information here?
		if externalRefs.URL != "" {
			links = append(links, externalRefs.URL)
		}
	}

	// duplicate the vulnerabilities based on the set of unique packages the vulnerability is for
	for _, p := range uniquePkgs.All() {
		matches := uniquePkgs.Matches(p)
		cpes := internal.NewStringSet()
		for _, m := range matches {
			cpes.Add(m.Criteria)
		}

		// create vulnerability entry
		vuln := grypeDB.Vulnerability{
			ID:                   vulnerability.ID,
			RecordSource:         recordSource,
			VersionConstraint:    buildConstraints(uniquePkgs.Matches(p)),
			VersionFormat:        "unknown", // TODO: derive this from the target software
			PackageName:          p.Product,
			Namespace:            "nvd", // should the vendor be here? or in other metadata?
			ProxyVulnerabilities: []string{},
			CPEs:                 cpes.ToSlice(),
		}

		allVulns = append(allVulns, vuln)
	}

	// If all the CPEs are invalid and no vulnerabilities were generated then there is no point
	// in creating metadata, so just return
	if len(allVulns) == 0 {
		return nil, nil
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	allCVSS := vulnerability.CVSS()

	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.ID,
		RecordSource: recordSource,
		Severity:     nvd.CvssSummaries(allCVSS).Sorted().Severity(),
		Links:        links,
		Description:  vulnerability.Description(),
	}

	for _, c := range allCVSS {
		if strings.HasPrefix(c.Version, "2.") {
			newCvss := &grypeDB.Cvss{
				BaseScore: c.BaseScore,
				Vector:    c.Vector,
			}
			if c.ExploitabilityScore != nil {
				newCvss.ExploitabilityScore = *c.ExploitabilityScore
			}
			if c.ImpactScore != nil {
				newCvss.ImpactScore = *c.ImpactScore
			}
			metadata.CvssV2 = newCvss
			break
		}
	}

	for _, c := range allCVSS {
		if strings.HasPrefix(c.Version, "3.") {
			newCvss := &grypeDB.Cvss{
				BaseScore: c.BaseScore,
				Vector:    c.Vector,
			}
			if c.ExploitabilityScore != nil {
				newCvss.ExploitabilityScore = *c.ExploitabilityScore
			}
			if c.ImpactScore != nil {
				newCvss.ImpactScore = *c.ImpactScore
			}
			metadata.CvssV3 = newCvss
			break
		}
	}

	return transformers.NewEntries(allVulns, metadata), nil
}
