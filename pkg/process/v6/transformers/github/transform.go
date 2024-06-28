package github

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"strings"
)

func Transform(vulnerability unmarshal.GitHubAdvisory, state provider.State) ([]data.Entry, error) {
	var blobs []grypeDB.Blob

	cleanDescription := strings.TrimSpace(vulnerability.Advisory.Summary)
	var descriptionDigest string
	if cleanDescription != "" {
		descriptionDigest = grypeDB.BlobDigest(cleanDescription)
		blobs = append(blobs, grypeDB.Blob{
			Digest: descriptionDigest,
			Value:  cleanDescription,
		})
	}

	vuln := grypeDB.Vulnerability{
		ProviderID: state.Provider,
		Provider: &grypeDB.Provider{
			ID:           state.Provider,
			Version:      state.Schema.Version,
			Processor:    "vunnel", // TODO: figure this
			DateCaptured: &state.Timestamp,
			InputDigest:  state.Listing.Algorithm + ":" + state.Listing.Digest, // TODO: unsafe pointer access
			//InstanceCacheURL: "",                                                   // TODO figure this
			//SourceURL:        "",                                                   // TODO figure this
		},
		Name: vulnerability.Advisory.GhsaID,
		//Modified:      "",                // TODO: should be pointer? need to change unmarshallers to account for this
		//Published:     "",                // TODO: should be pointer? need to change unmarshallers to account for this
		//Withdrawn:     "",                // TODO: should be pointer? need to change unmarshallers to account for this
		//SummaryDigest: "",                // TODO: need access to digest store too
		DetailDigest: descriptionDigest, // TODO: need access to digest store too
		References:   getReferences(vulnerability),
		//Related:      nil, // TODO: find examples for this... odds are aliases is what we want most of the time
		Aliases:    getAliases(vulnerability),
		Severities: getSeverities(vulnerability),
		//DbSpecificNvd: nil, // TODO: N/A for OS, are the others we should be considering though per distro?
		Affected: getAffecteds(vulnerability),
	}

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespaces combo) while merging
	// constraint ranges as they are found.
	//for idx, fixedInEntry := range vulnerability.Advisory.FixedIn {
	//	constraint := common.EnforceSemVerConstraint(fixedInEntry.Range)
	//
	//	var versionFormat string
	//	switch entryNamespace {
	//	case "github:language:python":
	//		versionFormat = "python"
	//	default:
	//		versionFormat = "unknown"
	//	}
	//
	//	// create vulnerability entry
	//	allVulns = append(allVulns, grypeDB.Vulnerability{
	//		ID:                     vulnerability.Advisory.GhsaID,
	//		VersionConstraint:      constraint,
	//		VersionFormat:          versionFormat,
	//		RelatedVulnerabilities: getRelatedVulnerabilities(vulnerability),
	//		PackageName:            grypeNamespace.Resolver().Normalize(fixedInEntry.Name),
	//		Namespace:              entryNamespace,
	//		Fix:                    getFix(vulnerability, idx),
	//	})
	//}
	//
	//// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	//metadata := grypeDB.VulnerabilityMetadata{
	//	ID:           vulnerability.Advisory.GhsaID,
	//	DataSource:   vulnerability.Advisory.URL,
	//	Namespace:    entryNamespace,
	//	RecordSource: recordSource,
	//	Severity:     vulnerability.Advisory.Severity,
	//	URLs:         []string{vulnerability.Advisory.URL},
	//	Description:  vulnerability.Advisory.Summary,
	//	Cvss:         getCvss(vulnerability),
	//}

	return transformers.NewEntries(vuln, blobs...), nil
}

func getAffecteds(vuln unmarshal.GitHubAdvisory) *[]grypeDB.Affected {
	var afs []grypeDB.Affected
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {

		for idx, fixedInEntry := range fixedIns {
			constraint := common.EnforceSemVerConstraint(fixedInEntry.Range)

			var versionFormat string
			switch vuln.Advisory.Namespace {
			case "pip":
				versionFormat = "python"
			default:
				versionFormat = "unknown"
			}

			afs = append(afs, grypeDB.Affected{
				Package: getPackage(group),
				//AffectedCpe:       getAffectedCPE(af), // TODO: this might not need to be done? unsure...
				//Versions:          getAffectedVersions(af), // TODO: do this later... there is no upstream support for this...
				//ExcludeVersions:   nil, // TODO...
				//Severities:        getAffectedSeverities(af) // TODO: this should be EMPTY if a top level severity exists (which is might)
				VersionConstraint: constraint,
				VersionFormat:     versionFormat, //Digests:           nil, // TODO...
				Fix:               getFix(vuln, idx),
			})
		}

	}
	return &afs
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

func getPackage(group groupIndex) *grypeDB.Package {
	return &grypeDB.Package{
		Name: group.name,
		Type: group.ecosystem,
	}
}

func getSeverities(vulnerability unmarshal.GitHubAdvisory) *[]grypeDB.Severity {
	var severities []grypeDB.Severity

	cleanSeverity := strings.ToLower(strings.TrimSpace(vulnerability.Advisory.Severity))

	if cleanSeverity != "" {
		severities = append(severities, grypeDB.Severity{
			Type:  "string", // TODO: enum
			Score: cleanSeverity,
		})
	}

	// TODO aren't there multiple CVSS upstream?

	if vulnerability.Advisory.CVSS != nil {
		severities = append(severities, grypeDB.Severity{
			// TODO: encode version
			Type:  "CVSS_V3", // TODO: enum
			Score: vulnerability.Advisory.CVSS.VectorString,
		})
	}

	//ret := datatypes.JSONSlice[grypeDB.Severity](severities)

	return &severities
}

func getAliases(vulnerability unmarshal.GitHubAdvisory) *[]grypeDB.Alias {
	var aliases []grypeDB.Alias
	for _, alias := range vulnerability.Advisory.CVE {
		aliases = append(aliases, grypeDB.Alias{
			Alias: alias,
		})
	}
	return &aliases
}

func getReferences(vulnerability unmarshal.GitHubAdvisory) *[]grypeDB.Reference {
	// TODO: are there no more links available upstream? this seems light...
	return &[]grypeDB.Reference{
		{
			Type: "ADVISORY", // TODO: enum
			URL:  vulnerability.Advisory.URL,
		},
	}

}

//func getFix(entry unmarshal.GitHubAdvisory, idx int) grypeDB.Fix {
//	fixedInEntry := entry.Advisory.FixedIn[idx]
//
//	var fixedInVersions []string
//	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Identifier)
//	if fixedInVersion != "" {
//		fixedInVersions = append(fixedInVersions, fixedInVersion)
//	}
//
//	fixState := grypeDB.NotFixedState
//	if len(fixedInVersions) > 0 {
//		fixState = grypeDB.FixedState
//	}
//
//	return grypeDB.Fix{
//		Versions: fixedInVersions,
//		State:    fixState,
//	}
//}
//
//func getRelatedVulnerabilities(entry unmarshal.GitHubAdvisory) []grypeDB.VulnerabilityReference {
//	vulns := make([]grypeDB.VulnerabilityReference, len(entry.Advisory.CVE))
//	for idx, cve := range entry.Advisory.CVE {
//		vulns[idx] = grypeDB.VulnerabilityReference{
//			ID:        cve,
//			Namespace: "nvd:cpe",
//		}
//	}
//	return vulns
//}
//
//func getCvss(entry unmarshal.GitHubAdvisory) (cvss []grypeDB.Cvss) {
//	if entry.Advisory.CVSS == nil {
//		return cvss
//	}
//
//	cvss = append(cvss, grypeDB.Cvss{
//		Version: entry.Advisory.CVSS.Version,
//		Vector:  entry.Advisory.CVSS.VectorString,
//		Metrics: grypeDB.NewCvssMetrics(
//			entry.Advisory.CVSS.BaseMetrics.BaseScore,
//			entry.Advisory.CVSS.BaseMetrics.ExploitabilityScore,
//			entry.Advisory.CVSS.BaseMetrics.ImpactScore,
//		),
//		VendorMetadata: transformers.VendorBaseMetrics{
//			BaseSeverity: entry.Advisory.CVSS.BaseMetrics.BaseSeverity,
//			Status:       entry.Advisory.CVSS.Status,
//		},
//	})
//
//	return cvss
//}
