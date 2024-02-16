package nvd

import (
	"fmt"
	"github.com/anchore/grype/grype/db/v5/purlvulnerability"
	"github.com/anchore/packageurl-go"
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

	return transformers.NewEntries(allVulns, processAdditionalEntries(vulnerability), metadata), nil
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

func processAdditionalEntries(vulnerability unmarshal.NVDVulnerability) purlvulnerability.Vulnerabilities {
	var result purlvulnerability.Vulnerabilities
	for _, entry := range vulnerability.AdditionalEntries {
		// TODO: DATA OVERRIDES: new vulnerability types! Need generic return value? Or a different strategy?
		//ns, err := namespaceFromPURL(entry.Package.Identifier)
		//if err != nil {
		//	// TODO: logging?
		//	continue
		//}
		//fix := grypeDB.Fix{
		//	State: grypeDB.UnknownFixState,
		//}
		//// TODO: WILL: loop, not if; handle multiple entries
		//if entry.Affected[0].Patched != "" {
		//	fix = grypeDB.Fix{
		//		State:    grypeDB.FixedState,
		//		Versions: []string{entry.Affected[0].Patched},
		//	}
		//}
		//// TODO: do I need an iteration per version constraint? I don't think so.
		//result = append(result, grypeDB.Vulnerability{
		//	ID: vulnerability.ID,
		//	//PackageQualifiers: qualifiers, // TODO: WILL: actual package qualifiers
		//	VersionConstraint: entry.Affected[0].Constraint,
		//	VersionFormat:     entry.Affected[0].Type,
		//	PackageName:       packageNameFromPurl(entry.Package.Identifier),
		//	Namespace:         ns.String(),
		//	Fix:               fix,
		//})
		purlVuln, err := purlVulnerabilityFromAdditionalVulnerability(entry, vulnerability.ID)
		if err != nil {
			continue
			// TODO: DATA OVERRIDES: do something smart
		}
		result = purlvulnerability.Merge(result, purlVuln)
	}
	return result
}

func purlVulnerabilityFromAdditionalVulnerability(entry unmarshal.AdditionalEntry, cveID string) (purlvulnerability.Vulnerabilities, error) {
	var result purlvulnerability.Vulnerabilities
	purl, err := packageurl.FromString(entry.Package.Identifier)
	if err != nil {
		return result, err
	}
	if purl.Type == "maven" {
		for _, v := range entry.Affected {
			var repositoryQualifier string
			qMap := purl.Qualifiers.Map()
			repositoryQualifier = qMap["repository"]
			if entry.Package.Qualifiers != nil && entry.Package.Qualifiers["respoitory"] != "" {
				repositoryQualifier = entry.Package.Qualifiers["repository"]
			}
			mavenVuln := purlvulnerability.Maven{
				ID:                     cveID,
				PackageNamespace:       purl.Namespace,
				PackageName:            purl.Name,
				VersionConstraint:      v.Constraint,
				VersionType:            v.Type,
				FixVersion:             v.Patched,
				ArtifactStatus:         artifactStatusFromVersionConstraint(v),
				RepositoryURLQualifier: repositoryQualifier,
			}
			result.Maven = append(result.Maven, mavenVuln)
		}
	}
	if purl.Type == "generic" {
		for _, v := range entry.Affected {
			var repositoryQualifier string
			qMap := purl.Qualifiers.Map()
			repositoryQualifier = qMap["repository"]
			if entry.Package.Qualifiers != nil && entry.Package.Qualifiers["respoitory"] != "" {
				repositoryQualifier = entry.Package.Qualifiers["repository"]
			}
			vendorQualifier := qMap["vendor"]
			if entry.Package.Qualifiers != nil && entry.Package.Qualifiers["vendor"] != "" {
				vendorQualifier = entry.Package.Qualifiers["vendor"]
			}

			genericVuln := purlvulnerability.Generic{
				ID:                  cveID,
				PackageName:         purl.Name,
				VersionConstraint:   v.Constraint,
				FixVersion:          v.Patched,
				ArtifactStatus:      artifactStatusFromVersionConstraint(v),
				RepositoryQualifier: repositoryQualifier,
				VendorQualifier:     vendorQualifier,
			}
			result.Generic = append(result.Generic, genericVuln)
		}
	}
	return result, nil
}

func artifactStatusFromVersionConstraint(v unmarshal.VersionIdentifier) string {
	// TODO: DATA OVERRIDES: this is incomplete
	switch v.Patched {
	case "":
		return "not-fixed"
	default:
		return "fixed"
	}
}

func namespaceFromPURL(purl string) (namespace.Namespace, error) {
	// TODO: WILL: more sustainable way to do this
	if strings.HasPrefix(purl, "pkg:maven") {
		return namespace.FromString("nvd:language:java")
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
	return ""
}
