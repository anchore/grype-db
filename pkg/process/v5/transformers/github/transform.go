package github

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v5/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/namespace"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func buildGrypeNamespace(group string) (namespace.Namespace, error) {
	feedGroupComponents := strings.Split(group, ":")

	if len(feedGroupComponents) < 2 {
		return nil, fmt.Errorf("unable to determine grype namespace for enterprise namespace=%s", group)
	}

	feedGroupLang := feedGroupComponents[1]
	syftLanguage := syftPkg.LanguageByName(feedGroupLang)

	if syftLanguage == syftPkg.UnknownLanguage {
		// For now map nuget to dotnet as the language.
		if feedGroupLang == "nuget" {
			syftLanguage = syftPkg.Dotnet
		} else {
			return nil, fmt.Errorf("unable to determine grype namespace for enterprise namespace=%s", group)
		}
	}

	ns, err := namespace.FromString(fmt.Sprintf("github:language:%s", string(syftLanguage)))

	if err != nil {
		return nil, err
	}

	return ns, nil
}

func Transform(vulnerability unmarshal.GitHubAdvisory) ([]data.Entry, error) {
	var allVulns []grypeDB.Vulnerability

	// Exclude entries marked as withdrawn
	if vulnerability.Advisory.Withdrawn != nil {
		return nil, nil
	}

	// TODO: stop capturing record source in the vulnerability metadata record (now that feed groups are not real)
	recordSource := fmt.Sprintf("github:%s", vulnerability.Advisory.Namespace)

	grypeNamespace, err := buildGrypeNamespace(vulnerability.Advisory.Namespace)
	if err != nil {
		return nil, err
	}

	entryNamespace := grypeNamespace.String()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespaces combo) while merging
	// constraint ranges as they are found.
	for idx, fixedInEntry := range vulnerability.Advisory.FixedIn {
		constraint := common.EnforceSemVerConstraint(fixedInEntry.Range)

		var versionFormat string
		switch entryNamespace {
		case "github:language:python":
			versionFormat = "python"
		default:
			versionFormat = "unknown"
		}

		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                     vulnerability.Advisory.GhsaID,
			VersionConstraint:      constraint,
			VersionFormat:          versionFormat,
			RelatedVulnerabilities: getRelatedVulnerabilities(vulnerability),
			PackageName:            grypeNamespace.Resolver().Normalize(fixedInEntry.Name),
			Namespace:              entryNamespace,
			Fix:                    getFix(vulnerability, idx),
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.Advisory.GhsaID,
		DataSource:   vulnerability.Advisory.URL,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     vulnerability.Advisory.Severity,
		URLs:         []string{vulnerability.Advisory.URL},
		Description:  vulnerability.Advisory.Summary,
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getFix(entry unmarshal.GitHubAdvisory, idx int) grypeDB.Fix {
	fixedInEntry := entry.Advisory.FixedIn[idx]

	var fixedInVersions []string
	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Identifier)
	if fixedInVersion != "" {
		fixedInVersions = append(fixedInVersions, fixedInVersion)
	}

	fixState := grypeDB.NotFixedState
	if len(fixedInVersions) > 0 {
		fixState = grypeDB.FixedState
	}

	return grypeDB.Fix{
		Versions: fixedInVersions,
		State:    fixState,
	}
}

func getRelatedVulnerabilities(entry unmarshal.GitHubAdvisory) []grypeDB.VulnerabilityReference {
	vulns := make([]grypeDB.VulnerabilityReference, len(entry.Advisory.CVE))
	for idx, cve := range entry.Advisory.CVE {
		vulns[idx] = grypeDB.VulnerabilityReference{
			ID:        cve,
			Namespace: "nvd:cpe",
		}
	}
	return vulns
}
