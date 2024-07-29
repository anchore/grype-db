package github

import (
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func Transform(vulnerability unmarshal.GitHubAdvisory, state provider.State) ([]data.Entry, error) {

	ins := []any{
		grypeDB.Provider{
			ID:           state.Provider,
			Version:      state.Schema.Version,
			Processor:    "vunnel", // TODO: figure this
			DateCaptured: &state.Timestamp,
			InputDigest:  state.Listing.Algorithm + ":" + state.Listing.Digest, // TODO: unsafe pointer access
			//InstanceCacheURL: "",                                                   // TODO figure this
			//SourceURL:        "",                                                   // TODO figure this
		},
		grypeDB.VulnerabilityHandle{
			Name: vulnerability.Advisory.GhsaID,
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:            vulnerability.Advisory.GhsaID,
				ProviderName:  state.Provider,
				Assigner:      nil, // TODO?
				Description:   strings.TrimSpace(vulnerability.Advisory.Summary),
				ModifiedDate:  internal.MustParseTime(vulnerability.Advisory.Updated),
				PublishedDate: internal.MustParseTime(vulnerability.Advisory.Published),
				Status:        grypeDB.VulnerabilityActive, // TODO
				References:    getReferences(vulnerability),
				Aliases:       getAliases(vulnerability),
				Severities:    getSeverities(vulnerability),
			},
		},
	}

	for _, a := range getAffected(vulnerability) {
		ins = append(ins, a)
	}

	return transformers.NewEntries(ins...), nil
}

func getAffected(vuln unmarshal.GitHubAdvisory) []grypeDB.AffectedPackageHandle {
	var afs []grypeDB.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {

		for idx, fixedInEntry := range fixedIns {

			afs = append(afs, grypeDB.AffectedPackageHandle{
				Package: getPackage(group),
				BlobValue: &grypeDB.AffectedBlob{
					CVEs:   getAliases(vuln),
					Ranges: getRanges(fixedInEntry, vuln, idx),
				},
			})
		}

	}
	return afs
}

func getRanges(fixedInEntry unmarshal.GithubFixedIn, vuln unmarshal.GitHubAdvisory, idx int) []grypeDB.AffectedRange {
	constraint := common.EnforceSemVerConstraint(fixedInEntry.Range)

	if constraint == "" {
		return nil
	}

	var versionFormat string
	switch vuln.Advisory.Namespace {
	case "pip":
		versionFormat = "python"
	default:
		versionFormat = "unknown"
	}

	return []grypeDB.AffectedRange{
		{
			Version: grypeDB.AffectedVersion{
				Type:       versionFormat, // TODO: unknown is blank?
				Constraint: constraint,
			},
			Fix: getFix(vuln, idx),
		},
	}

}

func getFix(entry unmarshal.GitHubAdvisory, idx int) *grypeDB.Fix {
	fixedInEntry := entry.Advisory.FixedIn[idx]

	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Identifier)

	fixState := "not-fixed" // TODO enum
	if len(fixedInVersion) > 0 {
		fixState = "fixed" // TODO enum
	}

	return &grypeDB.Fix{
		Version: fixedInVersion,
		State:   fixState,
	}
}

type groupIndex struct {
	name      string
	ecosystem string
}

func groupFixedIns(vuln unmarshal.GitHubAdvisory) map[groupIndex][]unmarshal.GithubFixedIn {
	grouped := make(map[groupIndex][]unmarshal.GithubFixedIn)

	for _, fixedIn := range vuln.Advisory.FixedIn {
		g := groupIndex{
			name:      fixedIn.Name,
			ecosystem: fixedIn.Ecosystem,
		}

		grouped[g] = append(grouped[g], fixedIn)
	}
	return grouped

}

func getPackageType(ecosystem string) string {
	switch ecosystem {
	case "composer":
		return "php-composer"
	case "rust":
		return "rust-crate"
	case "dart":
		return "dart-pub"
	case "nuget":
		return "dotnet"
	case "go":
		return "go-module"
	case "java":
		return "maven" // TODO: consider jankins-plugin as a separate type.  For now can determine based off of groupID
	case "npm":
		return "npm"
	case "gem":
		return "gem"
	case "python":
		return "python"
	case "swift":
		return "swift"
	}

	return ""
}

func getPackage(group groupIndex) *grypeDB.Package {
	return &grypeDB.Package{
		Name: group.name,
		Type: getPackageType(group.ecosystem),
	}
}

func getSeverities(vulnerability unmarshal.GitHubAdvisory) []grypeDB.Severity {
	var severities []grypeDB.Severity

	cleanSeverity := strings.ToLower(strings.TrimSpace(vulnerability.Advisory.Severity))

	if cleanSeverity != "" {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeHML, // TODO is this right?
			Value:  cleanSeverity,
		})
	}

	// TODO aren't there multiple CVSS upstream?

	if vulnerability.Advisory.CVSS != nil {
		severities = append(severities, grypeDB.Severity{
			// TODO: encode version
			Scheme: grypeDB.SeveritySchemeCVSSV3, // TODO version detection
			Value:  vulnerability.Advisory.CVSS.VectorString,
		})
	}

	return severities
}

func getAliases(vulnerability unmarshal.GitHubAdvisory) []string {
	var aliases []string
	for _, alias := range vulnerability.Advisory.CVE {
		aliases = append(aliases, alias)
	}
	return aliases
}

func getReferences(vulnerability unmarshal.GitHubAdvisory) []grypeDB.Reference {
	// TODO: are there no more links available upstream? this seems light...
	refs := []grypeDB.Reference{
		{
			//Type: "ADVISORY", // TODO: enum
			URL: vulnerability.Advisory.URL,
		},
	}

	return refs
}
