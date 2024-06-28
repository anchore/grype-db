package nvd

import (
	"encoding/json"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/syft/syft/cpe"
	"gorm.io/datatypes"
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
		Name:      vulnerability.ID,
		Modified:  vulnerability.LastModified,
		Published: vulnerability.Published,
		Withdrawn: "", // TODO: could get this from status?
		//SummaryDigest: nil,                       // TODO: need access to digest store too
		//DetailDigest:  strRef(descriptionDigest), // TODO: need access to digest store too
		DetailDigest: descriptionDigest,
		References:   getReferences(vulnerability),
		//Related:       nil,
		//Aliases:       nil,
		Severities: getSeverities(vulnerability),
		//DbSpecificNvd: getDBSpecific(vulnerability),
		//DbSpecific: getDBSpecific(vulnerability),
		Affected: getAffecteds(vulnerability),
	}

	return transformers.NewEntries(vuln, blobs...), nil
}

func getAffecteds(vulnerability unmarshal.NVDVulnerability) *[]grypeDB.Affected {
	uniquePkgs := findUniquePkgs(vulnerability.Configurations...)

	var affs []grypeDB.Affected
	for _, p := range uniquePkgs.All() {

		appMatches := uniquePkgs.ApplicationMatches(p)
		platMatches := uniquePkgs.PlatformMatches(p)

		affs = append(affs, grypeDB.Affected{
			Package:           getPackage(p),
			VersionConstraint: buildConstraints(appMatches),
			VersionFormat:     "unknown",
			Cpes:              getCPEs(appMatches.CPEs()),
			//Digests:                         nil,
			PlatformCpes: getPlatformCPEs(platMatches.CPEs()),
		})

	}
	return &affs
}

func getPackage(p pkgCandidate) *grypeDB.Package {
	if p.Product == "" {
		return nil
	}

	return &grypeDB.Package{
		//Ecosystem: "", // TODO: does this hint that ecosystem should be nullable?
		Name: strings.ToLower(p.Product), // TODO: this was normalized by the namespace... now this is ad-hoc... this seems bad
		//Purls:                           nil, // TODO: fill me in!

	}
}

func getCPEs(ins []string) *[]grypeDB.Cpe {
	if len(ins) == 0 {
		return nil
	}

	var cpes []grypeDB.Cpe

	for _, in := range ins {

		atts, err := cpe.NewAttributes(in)
		if err != nil {
			log.WithFields("cpe", in).Warn("could not parse CPE, dropping...")
			return nil
		}

		c := grypeDB.Cpe{
			ID: 0,
			//Schema:         "", // CPE version I think... do we know this?
			Type:            atts.Part,
			Vendor:          atts.Vendor,
			Product:         atts.Product,
			Edition:         atts.Edition,
			Language:        atts.Language,
			SoftwareEdition: atts.SWEdition,
			TargetHardware:  atts.TargetHW,
			TargetSoftware:  atts.TargetSW,
			Other:           atts.Other,
		}

		cpes = append(cpes, c)
	}

	return &cpes
}

func getPlatformCPEs(ins []string) *[]grypeDB.PlatformCpe {
	if len(ins) == 0 {
		return nil
	}

	var cpes []grypeDB.PlatformCpe

	for _, in := range ins {

		atts, err := cpe.NewAttributes(in)
		if err != nil {
			log.WithFields("cpe", in).Warn("could not parse platform CPE, dropping...")
			return nil
		}

		c := grypeDB.PlatformCpe{
			ID: 0,
			//Schema:         "", // CPE version I think... do we know this?
			Type:            atts.Part,
			Vendor:          atts.Vendor,
			Product:         atts.Product,
			Edition:         atts.Edition,
			Language:        atts.Language,
			Version:         atts.Version,
			VersionUpdate:   atts.Update,
			SoftwareEdition: atts.SWEdition,
			TargetHardware:  atts.TargetHW,
			TargetSoftware:  atts.TargetSW,
			Other:           atts.Other,
		}

		cpes = append(cpes, c)
	}

	return &cpes
}

func getDBSpecific(vuln unmarshal.NVDVulnerability) *datatypes.JSON {
	name := getStr(vuln.CisaVulnerabilityName)
	exploitAdd := getStr(vuln.CisaExploitAdd)
	actionDue := getStr(vuln.CisaActionDue)
	requiredAction := getStr(vuln.CisaRequiredAction)
	vulnStatus := getStr(vuln.VulnStatus)

	if name == "" && exploitAdd == "" && actionDue == "" && requiredAction == "" && vulnStatus == "" {
		return nil
	}

	obj := grypeDB.DbSpecificNvd{
		VulnStatus:            vulnStatus,
		CisaExploitAdd:        exploitAdd,
		CisaActionDue:         actionDue,
		CisaRequiredAction:    requiredAction,
		CisaVulnerabilityName: name,
	}

	by, err := json.Marshal(obj)
	if err != nil {
		panic(err) // TODO
	}

	ret := datatypes.JSON(by)

	return &ret
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
		priority := 2
		if i == 0 {
			priority = 1
		}
		results = append(results, grypeDB.Severity{
			Type:   "CVSS", // TODO: add version
			Score:  sev.Vector,
			Source: sev.Source,
			Rank:   priority,
		})
	}

	return &results
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
