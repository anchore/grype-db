package osv

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/codename"
	"github.com/anchore/grype-db/pkg/process/internal/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/pkg"
)

const (
	almaLinux = "almalinux"
	redHat    = "redhat"
	centos    = "centos"
	fedora    = "fedora"
	ubuntu    = "ubuntu"
	debian    = "debian"
	alpine    = "alpine"
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

	// Check if this is an advisory record
	if isAdvisoryRecord(vulnerability) {
		// For advisory records, emit unaffected packages
		for _, u := range getUnaffectedPackages(vulnerability) {
			in = append(in, u)
		}
	} else {
		// For vulnerability records, emit affected packages
		for _, a := range getAffectedPackages(vulnerability) {
			in = append(in, a)
		}
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
			Package:         getPackage(affected.Package),
			OperatingSystem: getOperatingSystemFromEcosystem(string(affected.Package.Ecosystem)),
			BlobValue:       &grypeDB.PackageBlob{CVEs: vuln.Aliases},
		}

		if withCPE {
			aph.BlobValue.Qualifiers = &grypeDB.PackageQualifiers{
				PlatformCPEs: cpes.([]string),
			}
		}

		var ranges []grypeDB.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, string(affected.Package.Ecosystem))...)
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
func getGrypeRangesFromRange(r models.Range, ecosystem string) []grypeDB.Range { // nolint: gocognit
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

	rangeType := normalizeRangeType(r.Type, ecosystem)
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
	if rangeType == "semver" || rangeType == "bitnami" {
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

func normalizeRangeType(t models.RangeType, ecosystem string) string {
	// For Bitnami ecosystem, use "bitnami" format instead of "semver"
	if ecosystem == "Bitnami" && t == models.RangeSemVer {
		return "bitnami"
	}

	switch t {
	case models.RangeSemVer, models.RangeEcosystem, models.RangeGit:
		return strings.ToLower(string(t))
	default:
		return "unknown"
	}
}

func getPackage(p models.Package) *grypeDB.Package {
	// Try to determine package type from ecosystem or PURL
	var pkgType pkg.Type
	var ecosystem string

	if p.Purl != "" {
		pkgType = pkg.TypeFromPURL(p.Purl)
		ecosystem = string(p.Ecosystem)
	} else {
		pkgType = getPackageTypeFromEcosystem(string(p.Ecosystem))
		// If we found a package type from OS ecosystem, use it; otherwise use original ecosystem
		if pkgType != "" {
			ecosystem = string(pkgType)
		} else {
			ecosystem = string(p.Ecosystem)
		}
	}

	return &grypeDB.Package{
		Ecosystem: ecosystem,
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// getPackageTypeFromEcosystem determines package type from OSV ecosystem
func getPackageTypeFromEcosystem(ecosystem string) pkg.Type {
	if ecosystem == "" {
		return ""
	}

	// Split ecosystem by colon to get OS name
	parts := strings.Split(ecosystem, ":")
	osName := strings.ToLower(parts[0])

	// Map OS names to package types
	switch osName {
	case almaLinux, redHat, centos, fedora, "amazonlinux", "oraclelinux", "sles", "mariner", "azurelinux":
		return pkg.RpmPkg
	case ubuntu, debian:
		return pkg.DebPkg
	case alpine, "chainguard", "wolfi", "minimos":
		return pkg.ApkPkg
	case "windows":
		return pkg.KbPkg
	default:
		// For non-OS ecosystems (like npm, pypi, etc.), return empty type
		// The package type will be determined from PURL if available
		return ""
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

// getOperatingSystemFromEcosystem extracts operating system information from OSV ecosystem field
// Examples: "AlmaLinux:8" -> almalinux 8, "Ubuntu:Pro:14.04:LTS" -> ubuntu 14.04
func getOperatingSystemFromEcosystem(ecosystem string) *grypeDB.OperatingSystem {
	if ecosystem == "" {
		return nil
	}

	// Split ecosystem by colon to get components
	parts := strings.Split(ecosystem, ":")
	if len(parts) < 2 {
		return nil
	}

	osName := strings.ToLower(parts[0])
	osVersion := parts[1]

	// Handle Ubuntu's more complex ecosystem format
	if osName == ubuntu && len(parts) > 2 {
		// Ubuntu:Pro:14.04:LTS -> version is 14.04
		if len(parts) >= 4 {
			osVersion = parts[2]
		}
	}

	// Parse version into major/minor components
	versionFields := strings.Split(osVersion, ".")
	var majorVersion, minorVersion string
	if len(versionFields) > 0 {
		majorVersion = versionFields[0]
		// Check if the first field is actually a number
		if _, err := strconv.Atoi(majorVersion[0:1]); err != nil {
			// If not numeric, treat the whole thing as a label version
			return &grypeDB.OperatingSystem{
				Name:         normalizeOSName(osName),
				LabelVersion: osVersion,
				Codename:     codename.LookupOS(normalizeOSName(osName), "", ""),
			}
		}
		if len(versionFields) > 1 {
			minorVersion = versionFields[1]
		}
	}

	return &grypeDB.OperatingSystem{
		Name:         normalizeOSName(osName),
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		Codename:     codename.LookupOS(normalizeOSName(osName), majorVersion, minorVersion),
	}
}

// normalizeOSName normalizes operating system names for consistency
func normalizeOSName(osName string) string {
	osName = strings.ToLower(osName)

	// Handle specific OS name mappings
	switch osName {
	case almaLinux:
		return almaLinux
	case ubuntu:
		return ubuntu
	case debian:
		return debian
	case alpine:
		return alpine
	case centos:
		return centos
	case "rhel", redHat:
		return redHat
	case fedora:
		return fedora
	case "opensuse", "suse":
		return "opensuse"
	case "arch":
		return "archlinux"
	default:
		// Try to lookup in distro mapping
		if d, ok := distro.IDMapping[osName]; ok {
			return d.String()
		}
		return osName
	}
}

// isAdvisoryRecord checks if the OSV record is marked as an advisory
func isAdvisoryRecord(vuln unmarshal.OSVVulnerability) bool {
	if vuln.DatabaseSpecific == nil {
		return false
	}

	vunnelData, ok := vuln.DatabaseSpecific["vunnel"]
	if !ok {
		return false
	}

	vunnelMap, ok := vunnelData.(map[string]any)
	if !ok {
		return false
	}

	recordType, ok := vunnelMap["record_type"]
	if !ok {
		return false
	}

	recordTypeStr, ok := recordType.(string)
	if !ok {
		return false
	}

	return recordTypeStr == "advisory"
}

// getUnaffectedPackages creates UnaffectedPackageHandle entries for advisory records
func getUnaffectedPackages(vuln unmarshal.OSVVulnerability) []grypeDB.UnaffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}

	var uphs []grypeDB.UnaffectedPackageHandle
	for _, affected := range vuln.Affected {
		uph := grypeDB.UnaffectedPackageHandle{
			Package:         getPackage(affected.Package),
			OperatingSystem: getOperatingSystemFromEcosystem(string(affected.Package.Ecosystem)),
			BlobValue:       getUnaffectedBlob(vuln.Aliases, affected.Ranges),
		}
		uphs = append(uphs, uph)
	}

	// stable ordering
	sort.Sort(internal.ByUnaffectedPackage(uphs))

	return uphs
}

// getUnaffectedBlob creates a package blob for unaffected packages (advisories)
// For advisories, we need to invert the ranges to represent unaffected versions
func getUnaffectedBlob(aliases []string, ranges []models.Range) *grypeDB.PackageBlob {
	var grypeRanges []grypeDB.Range
	for _, r := range ranges {
		grypeRanges = append(grypeRanges, getGrypeUnaffectedRangesFromRange(r)...)
	}

	return &grypeDB.PackageBlob{
		CVEs:   aliases,
		Ranges: grypeRanges,
	}
}

// getGrypeUnaffectedRangesFromRange converts OSV ranges to unaffected version ranges for unaffected packages
// This inverts the logic: instead of "< fix_version" (affected), we create ">= fix_version" (unaffected)
func getGrypeUnaffectedRangesFromRange(r models.Range) []grypeDB.Range {
	if len(r.Events) == 0 {
		return nil
	}

	fixByVersion := extractFixAvailability(r)
	rangeType := normalizeRangeType(r.Type)

	return buildUnaffectedRangesFromEvents(r.Events, fixByVersion, rangeType)
}

// extractFixAvailability extracts fix availability information from DatabaseSpecific
func extractFixAvailability(r models.Range) map[string]grypeDB.FixAvailability {
	fixByVersion := make(map[string]grypeDB.FixAvailability)

	dbSpecific, hasDBSpecific := r.DatabaseSpecific["anchore"]
	if !hasDBSpecific {
		return fixByVersion
	}

	anchoreInfo, isMap := dbSpecific.(map[string]any)
	if !isMap {
		return fixByVersion
	}

	fixes, hasFixes := anchoreInfo["fixes"]
	if !hasFixes {
		return fixByVersion
	}

	fixList, isList := fixes.([]any)
	if !isList {
		return fixByVersion
	}

	for _, fixEntry := range fixList {
		parseSingleFixEntry(fixEntry, fixByVersion)
	}

	return fixByVersion
}

// parseSingleFixEntry parses a single fix entry and adds it to the fixByVersion map
func parseSingleFixEntry(fixEntry any, fixByVersion map[string]grypeDB.FixAvailability) {
	fixMap, isMap := fixEntry.(map[string]any)
	if !isMap {
		return
	}

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

// buildUnaffectedRangesFromEvents processes events to create unaffected version ranges
func buildUnaffectedRangesFromEvents(events []models.Event, fixByVersion map[string]grypeDB.FixAvailability, rangeType string) []grypeDB.Range {
	var ranges []grypeDB.Range

	for _, e := range events {
		if e.Fixed != "" {
			unaffectedRange := createUnaffectedRange(e.Fixed, fixByVersion, rangeType)
			ranges = append(ranges, unaffectedRange)
		}
	}

	return ranges
}

// createUnaffectedRange creates a single safe range for a fixed version
func createUnaffectedRange(fixedVersion string, fixByVersion map[string]grypeDB.FixAvailability, rangeType string) grypeDB.Range {
	var detail *grypeDB.FixDetail
	if f, ok := fixByVersion[fixedVersion]; ok {
		detail = &grypeDB.FixDetail{
			Available: &f,
		}
	}

	constraint := fmt.Sprintf(">= %s", fixedVersion)
	return grypeDB.Range{
		Fix: normalizeFix(fixedVersion, detail),
		Version: grypeDB.Version{
			Type:       rangeType,
			Constraint: normalizeConstraint(constraint, rangeType),
		},
	}
}
