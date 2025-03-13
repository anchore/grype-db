package nvd

import (
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/syft/syft/cpe"
)

type Config struct {
	CPEParts            *strset.Set
	InferNVDFixVersions bool
}

func defaultConfig() Config {
	return Config{
		CPEParts:            strset.New("a"),
		InferNVDFixVersions: true,
	}
}

func Transformer(cfg Config) data.NVDTransformerV2 {
	if cfg == (Config{}) {
		cfg = defaultConfig()
	}
	return func(vulnerability unmarshal.NVDVulnerability, state provider.State) ([]data.Entry, error) {
		return transform(cfg, vulnerability, state)
	}
}

func transform(cfg Config, vulnerability unmarshal.NVDVulnerability, state provider.State) ([]data.Entry, error) {
	in := []any{
		grypeDB.VulnerabilityHandle{
			Name:          vulnerability.ID,
			ProviderID:    state.Provider,
			Provider:      internal.ProviderModel(state),
			ModifiedDate:  internal.ParseTime(vulnerability.LastModified),
			PublishedDate: internal.ParseTime(vulnerability.Published),
			Status:        getVulnStatus(vulnerability),
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:          vulnerability.ID,
				Assigners:   getAssigner(vulnerability),
				Description: strings.TrimSpace(vulnerability.Description()),
				References:  getReferences(vulnerability),
				Severities:  getSeverities(vulnerability),
			},
		},
	}

	for _, a := range getAffected(cfg, vulnerability) {
		in = append(in, a)
	}

	return transformers.NewEntries(in...), nil
}

func getAssigner(vuln unmarshal.NVDVulnerability) []string {
	if vuln.SourceIdentifier == nil {
		return nil
	}

	assigner := *vuln.SourceIdentifier

	if assigner == "" {
		return nil
	}

	return []string{assigner}
}

func getVulnStatus(vuln unmarshal.NVDVulnerability) grypeDB.VulnerabilityStatus {
	if vuln.VulnStatus == nil {
		return grypeDB.UnknownVulnerabilityStatus
	}

	// TODO: there is no path for withdrawn?

	// based off of the NVD or CVE list status, set the current vulnerability record status
	// see https://nvd.nist.gov/vuln/vulnerability-status
	s := strings.TrimSpace(strings.ReplaceAll(strings.ToLower(*vuln.VulnStatus), " ", ""))
	switch s {
	case "reserved", "received":
		// reserved (CVE list): A CVE Entry is marked as "RESERVED" when it has been reserved for use by a CVE Numbering Authority (CNA) or security
		//    researcher, but the details of it are not yet populated. A CVE Entry can change from the RESERVED state to being populated at any time
		//    based on a number of factors both internal and external to the CVE List.
		//
		// received (NVD): CVE has been recently published to the CVE List and has been received by the NVD.
		//
		return grypeDB.UnknownVulnerabilityStatus
	case "awaitinganalysis", "undergoinganalysis":
		// awaiting analysis (NVD): CVE has been marked for Analysis. Normally once in this state the CVE will be analyzed by NVD staff within 24 hours.
		//
		// undergoing analysis (NVD): CVE has been marked for Analysis. Normally once in this state the CVE will be analyzed by NVD staff within 24 hours.
		//
		return grypeDB.VulnerabilityAnalyzing
	case "disputed":
		// disputed (CVE list): When one party disagrees with another party's assertion that a particular issue in software is a vulnerability, a CVE Entry assigned
		//    to that issue may be designated as being "DISPUTED". In these cases, CVE is making no determination as to which party is correct. Instead, we make
		//    note of this dispute and try to offer any public references that will better inform those trying to understand the facts of the issue.
		//    When you see a CVE Entry that is "DISPUTED", we encourage you to research the issue through the references or by contacting the affected
		//    vendor or developer for more information.
		//
		return grypeDB.VulnerabilityDisputed
	case "rejected", "reject":
		// reject (CVE list): A CVE Entry listed as "REJECT" is a CVE Entry that is not accepted as a CVE Entry. The reason a CVE Entry is marked
		//    REJECT will most often be stated in the description of the CVE Entry. Possible examples include it being a duplicate CVE Entry, it being
		//    withdrawn by the original requester, it being assigned incorrectly, or some other administrative reason.
		//    As a rule, REJECT CVE Entries should be ignored.
		//
		// rejected (NVD): CVE has been marked as "**REJECT**" in the CVE List. These CVEs are stored in the NVD, but do not show up in search results.
		return grypeDB.VulnerabilityRejected
	case "modified", "analyzed", "published":
		// modified (NVD): CVE has been amended by a source (CVE Primary CNA or another CNA). Analysis data supplied by the NVD may be no longer be accurate due to these changes.
		//
		// analyzed (NVD): CVE has had analysis completed and all data associations made. Each Analysis has three sub-types, Initial, Modified and Reanalysis:
		//    Initial: Used to show the first time analysis was performed on a given CVE.
		//    Modified: Used to show that analysis was performed due to a modification the CVE’s information.
		//    Reanalysis: Used to show that new analysis occurred, but was not due to a modification from an external source.Analyzed CVEs do not show a banner on the vulnerability detail page.
		//
		// published (CVE list): The CVE Entry is populated with details. These are a CVE Description and reference link[s] regarding details of the CVE.
		//
		return grypeDB.VulnerabilityActive
	}

	return grypeDB.UnknownVulnerabilityStatus
}

func getAffected(cfg Config, vulnerability unmarshal.NVDVulnerability) []grypeDB.AffectedCPEHandle {
	uniquePkgs := findUniquePkgs(cfg, vulnerability.Configurations...)

	var affs []grypeDB.AffectedCPEHandle
	for _, p := range uniquePkgs.AllCandidates() {
		appMatches := uniquePkgs.ApplicationMatches(p)
		platformCPEs := uniquePkgs.PlatformMatches(p).CPEs()

		var qualifiers *grypeDB.AffectedPackageQualifiers
		if len(platformCPEs) > 0 {
			qualifiers = &grypeDB.AffectedPackageQualifiers{
				PlatformCPEs: platformCPEs,
			}
		}

		for _, c := range appMatches.CPEs() {
			affs = append(affs, grypeDB.AffectedCPEHandle{
				CPE: getCPEs(c),
				BlobValue: &grypeDB.AffectedPackageBlob{
					CVEs:       []string{vulnerability.ID},
					Qualifiers: qualifiers,
					Ranges:     getRanges(cfg, appMatches),
				},
			})
		}
	}
	return affs
}

func getRanges(cfg Config, matches applicationMatches) []grypeDB.AffectedRange {
	var ranges []grypeDB.AffectedRange
	for _, m := range matches {
		r := getRange(cfg, m)
		if r != nil {
			ranges = append(ranges, *r)
		}
	}

	return ranges
}

func getRange(cfg Config, match nvd.CpeMatch) *grypeDB.AffectedRange {
	return &grypeDB.AffectedRange{
		Version: grypeDB.AffectedVersion{
			Type:       "",
			Constraint: buildConstraints(match),
		},
		Fix: getFix(cfg, match),
	}
}

func getFix(cfg Config, match nvd.CpeMatch) *grypeDB.Fix {
	if !cfg.InferNVDFixVersions {
		return nil
	}

	possiblyFixed := strset.New()
	knownAffected := strset.New()
	unspecifiedSet := strset.New("*", "-", "*")

	if !match.Vulnerable {
		return nil
	}

	if match.VersionEndExcluding != nil && !unspecifiedSet.Has(*match.VersionEndExcluding) {
		possiblyFixed.Add(*match.VersionEndExcluding)
	}

	if match.VersionStartIncluding != nil && !unspecifiedSet.Has(*match.VersionStartIncluding) {
		knownAffected.Add(*match.VersionStartIncluding)
	}

	if match.VersionEndIncluding != nil && !unspecifiedSet.Has(*match.VersionEndIncluding) {
		knownAffected.Add(*match.VersionEndIncluding)
	}

	matchCPE, err := cpe.New(match.Criteria, cpe.DeclaredSource)
	if err != nil {
		log.WithFields("error", err, "cpe", match.Criteria).Warn("could not parse CPE as fix, dropping...")
		return nil
	}

	if !unspecifiedSet.Has(matchCPE.Attributes.Version) {
		knownAffected.Add(matchCPE.Attributes.Version)
	}

	possiblyFixed.Remove(knownAffected.List()...)

	if possiblyFixed.Size() != 1 {
		return nil
	}

	return &grypeDB.Fix{
		Version: possiblyFixed.List()[0],
		State:   grypeDB.FixedStatus,
	}
}

func getCPEs(in string) *grypeDB.Cpe {
	atts, err := cpe.NewAttributes(in)
	if err != nil {
		log.WithFields("cpe", in).Warn("could not parse CPE, dropping...")
		return nil
	}

	return &grypeDB.Cpe{
		Part:            atts.Part,
		Vendor:          atts.Vendor,
		Product:         atts.Product,
		Edition:         atts.Edition,
		Language:        atts.Language,
		SoftwareEdition: atts.SWEdition,
		TargetHardware:  atts.TargetHW,
		TargetSoftware:  atts.TargetSW,
		Other:           atts.Other,
	}
}
func getSeverities(vuln unmarshal.NVDVulnerability) []grypeDB.Severity {
	sevs := nvd.CvssSummaries(vuln.CVSS()).Sorted()
	var results []grypeDB.Severity
	for _, sev := range sevs {
		priority := 2
		if sev.Type == nvd.Primary {
			priority = 1
		}
		results = append(results, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCVSS,
			Value: grypeDB.CVSSSeverity{
				Vector:  sev.Vector,
				Version: sev.Version,
			},
			Source: sev.Source,
			Rank:   priority,
		})
	}

	return results
}

func getReferences(vuln unmarshal.NVDVulnerability) []grypeDB.Reference {
	references := []grypeDB.Reference{
		{
			URL: "https://nvd.nist.gov/vuln/detail/" + vuln.ID,
		},
	}
	for _, reference := range vuln.References {
		if reference.URL == "" {
			continue
		}
		// TODO there is other info we could be capturing too (source)
		references = append(references, grypeDB.Reference{
			URL:  reference.URL,
			Tags: grypeDB.NormalizeReferenceTags(reference.Tags),
		})
	}

	return references
}
