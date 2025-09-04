package osv

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

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

func Transform(vulnerability unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vulnerability)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	in := []any{
		grypeDB.VulnerabilityHandle{
			Name:          vulnerability.ID,
			ProviderID:    state.Provider,
			Provider:      internal.ProviderModel(state),
			Status:        grypeDB.VulnerabilityActive,
			ModifiedDate:  &vulnerability.Modified,
			PublishedDate: &vulnerability.Published,
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:          vulnerability.ID,
				Assigners:   nil,
				Description: vulnerability.Details,
				References:  getReferences(vulnerability),
				Aliases:     vulnerability.Aliases,
				Severities:  severities,
			},
		},
	}

	for _, a := range getAffectedPackages(vulnerability) {
		in = append(in, a)
	}

	return transformers.NewEntries(in...), nil
}

func getAffectedPackages(vuln unmarshal.OSVVulnerability) []grypeDB.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}

	// CPES might be in the database_specific information
	cpes, withCPE := vuln.DatabaseSpecific["cpes"]
	if withCPE {
		if _, ok := cpes.([]string); !ok {
			withCPE = false
		}
	}

	var aphs []grypeDB.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		aph := grypeDB.AffectedPackageHandle{
			Package:   getPackage(affected.Package),
			BlobValue: &grypeDB.PackageBlob{CVEs: vuln.Aliases},
		}

		if withCPE {
			aph.BlobValue.Qualifiers = &grypeDB.PackageQualifiers{
				PlatformCPEs: cpes.([]string),
			}
		}

		var ranges []grypeDB.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r)...)
		}
		aph.BlobValue.Ranges = ranges
		aphs = append(aphs, aph)
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(aphs))

	return aphs
}

// OSV supports flattered ranges, so both formats below are valid:
// "ranges": [
//
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    {
//	      "introduced": "12.0.0"
//	    },
//	    {
//	      "fixed": "12.18.4"
//	    }
//	  ]
//	},
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    {
//	      "introduced": "14.0.0"
//	    },
//	    {
//	      "fixed": "14.11.0"
//	    }
//	  ]
//	}
//
// ]
// "ranges": [
//
//	{
//	  "type": "SEMVER",
//	  "events": [
//		{
//		  "introduced": "12.0.0"
//		},
//		{
//		  "fixed": "12.18.4"
//		},
//		{
//		  "introduced": "14.0.0"
//		},
//		{
//		  "fixed": "14.11.0"
//		}
//	  ]
//	}
//
// ]
func getGrypeRangesFromRange(r models.Range) []grypeDB.Range { // nolint: gocognit
	var ranges []grypeDB.Range
	if len(r.Events) == 0 {
		return nil
	}

	var constraint string
	updateConstraint := func(c string) {
		if constraint == "" {
			constraint = c
		} else {
			constraint = common.AndConstraints(constraint, c)
		}
	}

	fixByVersion := make(map[string]grypeDB.FixAvailability)
	// check r.DatabaseSpecific for "anchore" key which has
	// {"fixes": [{
	//   "version": "v1.2.3",
	//   "date": "YYYY-MM-DD",
	//   "kind": "first-observed",
	// }]}

	if dbSpecific, ok := r.DatabaseSpecific["anchore"]; ok {
		if anchoreInfo, ok := dbSpecific.(map[string]any); ok {
			if fixes, ok := anchoreInfo["fixes"]; ok {
				if fixList, ok := fixes.([]any); ok {
					for _, fixEntry := range fixList {
						if fixMap, ok := fixEntry.(map[string]any); ok {
							version, vOk := fixMap["version"].(string)
							kind, kOk := fixMap["kind"].(string)
							date, dOk := fixMap["date"].(string)
							if vOk && kOk && dOk {
								fixByVersion[version] = grypeDB.FixAvailability{
									Date: internal.ParseTime(date),
									Kind: kind,
								}
							}
						}
					}
				}
			}
		}
	}

	rangeType := normalizeRangeType(r.Type)
	for _, e := range r.Events {
		switch {
		case e.Introduced != "" && e.Introduced != "0":
			constraint = fmt.Sprintf(">= %s", e.Introduced)
		case e.LastAffected != "":
			updateConstraint(fmt.Sprintf("<= %s", e.LastAffected))
			// We don't know the fix if last affected is set
			ranges = append(ranges, grypeDB.Range{
				Version: grypeDB.Version{
					Type:       rangeType,
					Constraint: normalizeConstraint(constraint, rangeType),
				},
			})
			// Reset the constraint
			constraint = ""
		case e.Fixed != "":
			var detail *grypeDB.FixDetail
			if f, ok := fixByVersion[e.Fixed]; ok {
				detail = &grypeDB.FixDetail{
					Available: &f,
				}
			}
			updateConstraint(fmt.Sprintf("< %s", e.Fixed))
			ranges = append(ranges, grypeDB.Range{
				Fix: normalizeFix(e.Fixed, detail),
				Version: grypeDB.Version{
					Type:       rangeType,
					Constraint: normalizeConstraint(constraint, rangeType),
				},
			})
			// Reset the constraint
			constraint = ""
		}
	}

	// Check if there's an event that "introduced" but never had a "fixed" or "last affected" event
	if constraint != "" {
		ranges = append(ranges, grypeDB.Range{
			Version: grypeDB.Version{
				Type:       rangeType,
				Constraint: normalizeConstraint(constraint, rangeType),
			},
		})
	}

	return ranges
}

func normalizeConstraint(constraint string, rangeType string) string {
	if rangeType == "semver" {
		return common.EnforceSemVerConstraint(constraint)
	}
	return constraint
}

func normalizeFix(fix string, detail *grypeDB.FixDetail) *grypeDB.Fix {
	fixedInVersion := common.CleanFixedInVersion(fix)
	fixState := grypeDB.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = grypeDB.FixedStatus
	}

	return &grypeDB.Fix{
		State:   fixState,
		Version: fixedInVersion,
		Detail:  detail,
	}
}

func normalizeRangeType(t models.RangeType) string {
	switch t {
	case models.RangeSemVer, models.RangeEcosystem, models.RangeGit:
		return strings.ToLower(string(t))
	default:
		return "unknown"
	}
}

func getPackage(p models.Package) *grypeDB.Package {
	return &grypeDB.Package{
		Ecosystem: string(p.Ecosystem),
		Name:      name.Normalize(p.Name, pkg.TypeFromPURL(p.Purl)),
	}
}

func getReferences(vuln unmarshal.OSVVulnerability) []grypeDB.Reference {
	var refs []grypeDB.Reference
	for _, ref := range vuln.References {
		refs = append(refs,
			grypeDB.Reference{
				URL:  ref.URL,
				Tags: []string{string(ref.Type)},
			},
		)
	}

	return refs
}

// extractCVSSInfo extracts the CVSS version and vector from the CVSS string
func extractCVSSInfo(cvss string) (string, string, error) {
	re := regexp.MustCompile(`^CVSS:(\d+\.\d+)/(.+)$`)
	matches := re.FindStringSubmatch(cvss)

	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid CVSS format")
	}

	return matches[1], matches[0], nil
}

func normalizeSeverity(severity models.Severity) (grypeDB.Severity, error) {
	switch severity.Type {
	case models.SeverityCVSSV2, models.SeverityCVSSV3, models.SeverityCVSSV4:
		version, vector, err := extractCVSSInfo(severity.Score)
		if err != nil {
			return grypeDB.Severity{}, err
		}

		return grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCVSS,
			Value: grypeDB.CVSSSeverity{
				Vector:  vector,
				Version: version,
			},
		}, nil
	default:
		return grypeDB.Severity{
			Scheme: grypeDB.UnknownSeverityScheme,
			Value:  severity.Score,
		}, nil
	}
}

func getSeverities(vuln unmarshal.OSVVulnerability) ([]grypeDB.Severity, error) {
	var severities []grypeDB.Severity
	for _, sev := range vuln.Severity {
		severity, err := normalizeSeverity(sev)
		if err != nil {
			return nil, err
		}
		severities = append(severities, severity)
	}

	for _, affected := range vuln.Affected {
		for _, sev := range affected.Severity {
			severity, err := normalizeSeverity(sev)
			if err != nil {
				return nil, err
			}
			severities = append(severities, severity)
		}
	}

	return severities, nil
}
