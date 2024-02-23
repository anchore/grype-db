package nvd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype-db/internal"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v5/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/platformcpe"
)

func Transform(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	// TODO: stop capturing record source in the vulnerability metadata record (now that feed groups are not real)
	recordSource := "nvdv2:nvdv2:cves"

	grypeNamespace, err := namespace.FromString("nvd:cpe")
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
		var qualifiers []qualifier.Qualifier
		matches := uniquePkgs.Matches(p)
		cpes := internal.NewStringSet()
		for _, m := range matches {
			cpes.Add(grypeNamespace.Resolver().Normalize(m.Criteria))
		}

		if p.PlatformCPE != "" {
			qualifiers = []qualifier.Qualifier{platformcpe.Qualifier{
				Kind: "platform-cpe",
				CPE:  p.PlatformCPE,
			}}
		}

		orderedCPEs := cpes.ToSlice()
		sort.Strings(orderedCPEs)

		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                vulnerability.ID,
			PackageQualifiers: qualifiers,
			VersionConstraint: buildConstraints(uniquePkgs.Matches(p)),
			VersionFormat:     "unknown",
			PackageName:       grypeNamespace.Resolver().Normalize(p.Product),
			Namespace:         entryNamespace,
			CPEs:              orderedCPEs,
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

	allVulns = append(allVulns, processAdditionalEntries(vulnerability)...)

	return transformers.NewEntries(allVulns, metadata), nil
}

func getCvss(cvss ...nvd.CvssSummary) []grypeDB.Cvss {
	var results []grypeDB.Cvss
	for _, c := range cvss {
		results = append(results, grypeDB.Cvss{
			Source:  c.Source,
			Type:    string(c.Type),
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

func processAdditionalEntries(vulnerability unmarshal.NVDVulnerability) []grypeDB.Vulnerability {
	var result []grypeDB.Vulnerability
	for _, entry := range vulnerability.AdditionalEntries {
		ns, err := namespaceFromPURL(entry.Package.Identifier)
		if err != nil {
			// TODO: logging?
			continue
		}
		fix := grypeDB.Fix{
			State: grypeDB.UnknownFixState,
		}
		// TODO: WILL: loop, not if; handle multiple entries
		if entry.Affected[0].Patched != "" {
			fix = grypeDB.Fix{
				State:    grypeDB.FixedState,
				Versions: []string{entry.Affected[0].Patched},
			}
		}
		// TODO: do I need an iteration per version constraint? I don't think so.
		result = append(result, grypeDB.Vulnerability{
			ID: vulnerability.ID,
			//PackageQualifiers: qualifiers, // TODO: WILL: actual package qualifiers
			VersionConstraint: entry.Affected[0].Constraint,
			VersionFormat:     entry.Affected[0].Type,
			PackageName:       packageNameFromPurl(entry.Package.Identifier),
			Namespace:         ns.String(),
			MetadataNamespace: "nvd:cpe", // TODO: WILL: stop hard-coding
			Fix:               fix,
		})
	}
	return result
}

func namespaceFromPURL(purl string) (namespace.Namespace, error) {
	// TODO: WILL: more sustainable way to do this
	if strings.HasPrefix(purl, "pkg:maven") {
		return namespace.FromString("nvd:language:java")
	}

	if strings.HasPrefix(purl, "pkg:generic") {
		return namespace.FromString("nvd:generic")
	}
	return nil, fmt.Errorf("unable to make namespace from %s", purl)
}

func packageNameFromPurl(purl string) string {
	// TODO: WILL: sustainable / correct way to do this
	if strings.HasPrefix(purl, "pkg:maven") {
		parts := strings.Split(purl, "/")
		if len(parts) == 3 {
			return fmt.Sprintf("%s:%s", parts[1], parts[2])
		}
	}

	if strings.HasPrefix(purl, "pkg:generic") {
		parts := strings.Split(purl, "/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return ""
}
