package github

import (
	"sort"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(vulnerability unmarshal.GitHubAdvisory, state provider.State) ([]data.Entry, error) {
	ins := []any{
		getVulnerability(vulnerability, state),
	}

	for _, a := range getAffectedPackage(vulnerability) {
		ins = append(ins, a)
	}

	return transformers.NewEntries(ins...), nil
}

func getVulnerability(vuln unmarshal.GitHubAdvisory, state provider.State) grypeDB.VulnerabilityHandle {
	return grypeDB.VulnerabilityHandle{
		Name:          vuln.Advisory.GhsaID,
		ProviderID:    state.Provider,
		Provider:      internal.ProviderModel(state),
		ModifiedDate:  internal.ParseTime(vuln.Advisory.Updated),
		PublishedDate: internal.ParseTime(vuln.Advisory.Published),
		WithdrawnDate: internal.ParseTime(vuln.Advisory.Withdrawn),
		Status:        getVulnStatus(vuln),
		BlobValue: &grypeDB.VulnerabilityBlob{
			ID: vuln.Advisory.GhsaID,
			// it does not appear to be possible to get "credits" or any user information from the graphql API
			// for security advisories (see https://docs.github.com/en/graphql/reference/queries#securityadvisories),
			// thus assigner is left empty.
			Assigners:   nil,
			Description: strings.TrimSpace(vuln.Advisory.Summary),
			References:  getReferences(vuln),
			Aliases:     getAliases(vuln),
			Severities:  getSeverities(vuln),
		},
	}
}

func getVulnStatus(vuln unmarshal.GitHubAdvisory) grypeDB.VulnerabilityStatus {
	if vuln.Advisory.Withdrawn == "" {
		return grypeDB.VulnerabilityActive
	}

	return grypeDB.VulnerabilityRejected
}

func getAffectedPackage(vuln unmarshal.GitHubAdvisory) []grypeDB.AffectedPackageHandle {
	var afs []grypeDB.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		for _, fixedInEntry := range fixedIns {
			afs = append(afs, grypeDB.AffectedPackageHandle{
				Package: getPackage(group),
				BlobValue: &grypeDB.AffectedPackageBlob{
					CVEs:   getAliases(vuln),
					Ranges: getRanges(fixedInEntry),
				},
			})
		}
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(afs))

	return afs
}

func getRanges(fixedInEntry unmarshal.GithubFixedIn) []grypeDB.AffectedRange {
	return []grypeDB.AffectedRange{
		{
			Version: grypeDB.AffectedVersion{
				Type:       getAffectedVersionFormat(fixedInEntry),
				Constraint: common.EnforceSemVerConstraint(fixedInEntry.Range),
			},
			Fix: getFix(fixedInEntry),
		},
	}
}

func getAffectedVersionFormat(fixedInEntry unmarshal.GithubFixedIn) string {
	versionFormat := strings.ToLower(fixedInEntry.Ecosystem)

	if versionFormat == "pip" {
		versionFormat = "python"
	}

	return versionFormat
}

func getFix(fixedInEntry unmarshal.GithubFixedIn) *grypeDB.Fix {
	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Identifier)

	fixState := grypeDB.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = grypeDB.FixedStatus
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

func getPackageType(ecosystem string) pkg.Type {
	ecosystem = strings.ToLower(ecosystem)
	switch ecosystem {
	case "composer":
		return pkg.PhpComposerPkg
	case "rust", "cargo":
		return pkg.RustPkg
	case "dart":
		return pkg.DartPubPkg
	case "nuget", ".net":
		return pkg.DotnetPkg
	case "go", "golang":
		return pkg.GoModulePkg
	case "maven", "java":
		return pkg.JavaPkg
	case "npm":
		return pkg.NpmPkg
	case "pypi", "python", "pip":
		return pkg.PythonPkg
	case "swift":
		return pkg.SwiftPkg
	case "rubygems", "ruby", "gem":
		return pkg.GemPkg
	case "apk":
		return pkg.ApkPkg
	case "rpm":
		return pkg.RpmPkg
	case "deb":
		return pkg.DebPkg
	}

	log.Warnf("using unknown ecosystem intead of syft pkg type (this will probably cause issues when matching): %q", ecosystem)

	return pkg.Type(ecosystem)
}

func getPackage(group groupIndex) *grypeDB.Package {
	t := getPackageType(group.ecosystem)
	return &grypeDB.Package{
		Name:      name.Normalize(group.name, t),
		Ecosystem: string(t),
	}
}

func getSeverities(vulnerability unmarshal.GitHubAdvisory) []grypeDB.Severity {
	var severities []grypeDB.Severity

	// the string severity and CVSS is not necessarily correlated (nor is CVSS guaranteed to be provided
	// at all... see https://github.com/advisories/GHSA-xwg4-93c6-3h42 for example), so we need to keep them separate
	cleanSeverity := strings.ToLower(strings.TrimSpace(vulnerability.Advisory.Severity))

	if cleanSeverity != "" {
		severities = append(severities, grypeDB.Severity{
			// This is the string severity based off of CVSS v3
			// see https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database?learn=security_advisories&learnProduct=code-security#about-cvss-levels
			Scheme: grypeDB.SeveritySchemeCHML,
			Value:  cleanSeverity,
		})
	}

	if vulnerability.Advisory.CVSS != nil {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCVSS,
			Value: grypeDB.CVSSSeverity{
				Vector:  vulnerability.Advisory.CVSS.VectorString,
				Version: vulnerability.Advisory.CVSS.Version,
			},
		})
	}

	return severities
}

func getAliases(vulnerability unmarshal.GitHubAdvisory) (aliases []string) {
	aliases = append(aliases, vulnerability.Advisory.CVE...)
	return
}

func getReferences(vulnerability unmarshal.GitHubAdvisory) []grypeDB.Reference {
	// TODO: The additional reference links are not currently captured in the vunnel result, but should be enhanced to
	// https://github.com/anchore/vunnel/issues/646 to capture this
	refs := []grypeDB.Reference{
		{
			URL: vulnerability.Advisory.URL,
		},
	}

	return refs
}
