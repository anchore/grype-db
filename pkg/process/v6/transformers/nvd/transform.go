package nvd

import (
	"github.com/anchore/grype-db/internal"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/syft/syft/cpe"
	"sort"
	"strings"
)

func Transform(vulnerability unmarshal.NVDVulnerability, state provider.State) ([]data.Entry, error) {
	var blobs []grypeDB.Blob

	cleanDescription := strings.TrimSpace(vulnerability.Description())
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
		Name:          vulnerability.ID,
		Modified:      strRef(vulnerability.LastModified),
		Published:     strRef(vulnerability.Published),
		Withdrawn:     nil,                       // TODO: could get this from status?
		SummaryDigest: nil,                       // TODO: need access to digest store too
		DetailDigest:  strRef(descriptionDigest), // TODO: need access to digest store too
		References:    getReferences(vulnerability),
		//Related:       nil,
		//Aliases:       nil,
		Severities:    getSeverities(vulnerability),
		DbSpecificNvd: getDBSpecific(vulnerability),
		Affected:      getAffecteds(vulnerability),
	}

	return transformers.NewEntries(vuln, blobs...), nil
}

func getAffecteds(vulnerability unmarshal.NVDVulnerability) *[]grypeDB.Affected {
	uniquePkgs := findUniquePkgs(vulnerability.Configurations...)

	var affs []grypeDB.Affected
	for _, p := range uniquePkgs.All() {
		affs = append(affs, grypeDB.Affected{
			Package:  getPackage(p, &uniquePkgs),
			Versions: nil, // TODO: this might be the spot to use this...
			//ExcludeVersions: nil,
			//Severities:      nil,
			Range: getRanges(uniquePkgs.Matches(p)),
			//Digests:         nil,
		})
	}
	return &affs
}

func getRanges(matches []nvd.CpeMatch) *[]grypeDB.Range {
	if len(matches) == 0 {
		return nil
	}
	return &[]grypeDB.Range{
		{
			Type: "UNKNOWN", // TODO: not in specified enum, should just be empty?
			//Repo:       nil,
			Events: getRangesEvents(matches),
		},
	}
}

func getRangesEvents(matches []nvd.CpeMatch) *[]grypeDB.RangeEvent {

	var results []grypeDB.RangeEvent
	for _, r := range matches {
		if !r.Vulnerable {
			continue
		}

		// TODO: this logic isn't quite right... fixme

		var introduced string
		if r.VersionStartIncluding != nil {
			introduced = *r.VersionStartIncluding
		} else if r.VersionStartExcluding != nil {
			introduced = *r.VersionStartExcluding
		}

		var lastAffected string
		if r.VersionEndIncluding != nil {
			lastAffected = *r.VersionEndIncluding
		} else if r.VersionEndExcluding != nil {
			lastAffected = *r.VersionEndExcluding
		}

		results = append(results, grypeDB.RangeEvent{
			ID:           0,
			Introduced:   strRef(introduced),
			Fixed:        nil,
			LastAffected: strRef(lastAffected),
			Limit:        nil,
			State:        "unknown", // TODO enum and leave blank for unkonwn?
		})

	}

	return &results
}

func getPackage(p pkgCandidate, uniquePkgs *uniquePkgTracker) *grypeDB.Package {
	if p.Product == "" {
		return nil
	}

	matches := uniquePkgs.Matches(p)
	cpes := internal.NewStringSet()
	for _, m := range matches {
		cpes.Add(strings.ToLower(m.Criteria)) // TODO: this was normalized by the namespace... now this is ad-hoc... this seems bad
	}

	return &grypeDB.Package{
		//Ecosystem: "", // TODO: does this hint that ecosystem should be nullable?
		PackageName: strings.ToLower(p.Product), // TODO: this was normalized by the namespace... now this is ad-hoc... this seems bad
		//Purls:                           nil, // TODO: fill me in!
		Cpes: getCPEs(cpes.ToSlice()),
		//Digests:                         nil,
		PackageQualifierPlatformCpes: getPlatformCpes(p.PlatformCPE),
	}
}

func getPlatformCpes(in string) *[]grypeDB.PackageQualifierPlatformCpe {
	if in == "" {
		return nil

	}

	return &[]grypeDB.PackageQualifierPlatformCpe{
		{
			Cpe: in,
		},
	}
}

func getCPEs(ins []string) *[]grypeDB.Cpe {
	if len(ins) == 0 {
		return nil
	}

	sort.Strings(ins)

	var cpes []grypeDB.Cpe

	for _, in := range ins {
		atts, err := cpe.NewAttributes(in)
		if err != nil {
			log.WithFields("cpe", in).Warn("could not parse CPE, dropping...")
			continue
		}

		cpes = append(cpes, grypeDB.Cpe{
			//Schema:         "", // CPE version I think... do we know this?
			Type:           "",
			Vendor:         strRef(atts.Vendor),
			Product:        atts.Product,
			Version:        strRef(atts.Version),
			Update:         strRef(atts.Update),
			TargetSoftware: strRef(atts.TargetSW),
		})
	}

	return &cpes
}

func getDBSpecific(vuln unmarshal.NVDVulnerability) *[]grypeDB.DbSpecificNvd {
	name := getStr(vuln.CisaVulnerabilityName)
	exploitAdd := getStr(vuln.CisaExploitAdd)
	actionDue := getStr(vuln.CisaActionDue)
	requiredAction := getStr(vuln.CisaRequiredAction)
	vulnStatus := getStr(vuln.VulnStatus)

	if name == "" && exploitAdd == "" && actionDue == "" && requiredAction == "" && vulnStatus == "" {
		return nil
	}

	return &[]grypeDB.DbSpecificNvd{
		{
			VulnStatus:            vulnStatus,
			CisaExploitAdd:        exploitAdd,
			CisaActionDue:         actionDue,
			CisaRequiredAction:    requiredAction,
			CisaVulnerabilityName: name,
		},
	}
}

func getStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getSeverities(vuln unmarshal.NVDVulnerability) *[]grypeDB.Severity {
	sevs := nvd.CvssSummaries(vuln.CVSS()).Sorted()
	var results []grypeDB.Severity
	for i, sev := range sevs {
		priority := "secondary"
		if i == 0 {
			priority = "primary"
		}
		results = append(results, grypeDB.Severity{
			Type:     "CVSS", // TODO: add version
			Score:    sev.Vector,
			Source:   strRef(sev.Source),
			Priority: strRef(priority),
		})
	}
	return &results
}

func strRef(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func getReferences(vuln unmarshal.NVDVulnerability) *[]grypeDB.Reference {
	references := []grypeDB.Reference{
		{
			URL: "https://nvd.nist.gov/vuln/detail/" + vuln.ID,
		},
	}
	for _, reference := range vuln.References {
		if reference.URL == "" {
			continue
		}
		// TODO there is other info we could be capturing too...
		references = append(references, grypeDB.Reference{
			//Type: , // TODO: add this in...
			URL: reference.URL,
		})
	}
	return &references
}