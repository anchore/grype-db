package nvd

import (
	"fmt"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype-db/pkg/db/v3"
	"github.com/anchore/grype-db/pkg/process/v3/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
)

const (
	// TODO: tech debt from a previous design
	feed  = "nvdv2"
	group = "nvdv2:cves"
)

func Transform(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	recordSource := grypeDB.RecordSource(feed, group)
	entryNamespace, err := grypeDB.NamespaceForFeedGroup(feed, group)
	if err != nil {
		return nil, err
	}

	uniquePkgs := findUniquePkgs(vulnerability.Configurations...)

	if err != nil {
		return nil, fmt.Errorf("unable to parse NVD entry: %w", err)
	}

	// extract all links
	var links []string
	for _, externalRefs := range vulnerability.References {
		// TODO: should we capture other information here?
		if externalRefs.URL != "" {
			links = append(links, externalRefs.URL)
		}
	}

	// duplicate the vulnerabilities based on the set of unique packages the vulnerability is for
	var allVulns []grypeDB.Vulnerability
	for _, p := range uniquePkgs.All() {
		matches := uniquePkgs.Matches(p)
		cpes := strset.New()
		for _, m := range matches {
			cpes.Add(m.Criteria)
		}

		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                vulnerability.ID,
			VersionConstraint: buildConstraints(uniquePkgs.Matches(p)),
			VersionFormat:     "unknown",
			PackageName:       p.Product,
			Namespace:         entryNamespace,
			CPEs:              cpes.List(),
			Fix: grypeDB.Fix{
				State: grypeDB.UnknownFixState,
			},
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	allCVSS := vulnerability.CVSS()
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.ID,
		DataSource:   "https://nvd.nist.gov/vuln/detail/" + vulnerability.ID,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     nvd.CvssSummaries(allCVSS).Sorted().Severity(),
		URLs:         links,
		Description:  vulnerability.Description(),
		Cvss:         getCvss(allCVSS...),
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getCvss(cvss ...nvd.CvssSummary) []grypeDB.Cvss {
	var results []grypeDB.Cvss
	for _, c := range cvss {
		results = append(results, grypeDB.Cvss{
			Version: c.Version,
			Vector:  c.Vector,
			Metrics: grypeDB.CvssMetrics{
				BaseScore:           c.BaseScore,
				ExploitabilityScore: c.ExploitabilityScore,
				ImpactScore:         c.ImpactScore,
			},
		})
	}
	return results
}
