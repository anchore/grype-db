package nvd

import (
	"fmt"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype-db/pkg/db/v4"
	"github.com/anchore/grype-db/pkg/db/v4/namespace"
	"github.com/anchore/grype-db/pkg/process/v4/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
)

const (
	// TODO: tech debt from a previous design
	feed  = "nvdv2"
	group = "nvdv2:cves"
)

func buildGrypeNamespace(feed, group string) (namespace.Namespace, error) {
	if feed != "nvdv2" || group != "nvdv2:cves" {
		return nil, fmt.Errorf("invalid source for feed=%s, group=%s", feed, group)
	}

	ns, err := namespace.FromString("nvd:cpe")

	if err != nil {
		return nil, err
	}

	return ns, nil
}

func Transform(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	recordSource := fmt.Sprintf("%s:%s", feed, group)
	grypeNamespace, err := buildGrypeNamespace(feed, group)
	if err != nil {
		return nil, err
	}

	entryNamespace := grypeNamespace.String()

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
	var allVulns []grypeDB.Vulnerability
	for _, p := range uniquePkgs.All() {
		matches := uniquePkgs.Matches(p)
		cpes := strset.New()
		for _, m := range matches {
			cpes.Add(grypeNamespace.Resolver().Normalize(m.Criteria))
		}

		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                vulnerability.ID,
			VersionConstraint: buildConstraints(uniquePkgs.Matches(p)),
			VersionFormat:     "unknown",
			PackageName:       grypeNamespace.Resolver().Normalize(p.Product),
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
