package os

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/codename"
	"github.com/anchore/grype-db/pkg/process/internal/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(vulnerability unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	in := []any{
		internal.ProviderModel(state),
		grypeDB.VulnerabilityHandle{
			Name: vulnerability.Vulnerability.Name,
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:            vulnerability.Vulnerability.Name,
				ProviderName:  state.Provider,
				Assigners:     nil,
				Description:   strings.TrimSpace(vulnerability.Vulnerability.Description),
				Status:        grypeDB.VulnerabilityActive,
				References:    getReferences(vulnerability),
				Aliases:       getAliases(vulnerability),
				Severities:    getSeverities(vulnerability),
				ModifiedDate:  internal.ParseTime(vulnerability.Vulnerability.Metadata.Updated),
				PublishedDate: internal.ParseTime(vulnerability.Vulnerability.Metadata.Issued),
			},
		},
	}

	for _, a := range getAffectedPackages(vulnerability) {
		in = append(in, a)
	}

	return transformers.NewEntries(in...), nil
}

func getAffectedPackages(vuln unmarshal.OSVulnerability) []grypeDB.AffectedPackageHandle {
	var afs []grypeDB.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		var qualifiers *grypeDB.AffectedPackageQualifiers
		if group.module != "" {
			qualifiers = &grypeDB.AffectedPackageQualifiers{
				RpmModularity: group.module,
			}
		}

		aph := grypeDB.AffectedPackageHandle{
			OperatingSystem: getOperatingSystem(group.osName, group.osVersion),
			Package:         getPackage(group),

			BlobValue: &grypeDB.AffectedPackageBlob{
				CVEs:       getAliases(vuln),
				Qualifiers: qualifiers,
				Ranges:     nil,
			},
		}

		var ranges []grypeDB.AffectedRange
		for _, fixedInEntry := range fixedIns {
			ranges = append(ranges, grypeDB.AffectedRange{
				Version: grypeDB.AffectedVersion{
					Type:       fixedInEntry.VersionFormat,
					Constraint: enforceConstraint(fixedInEntry.Version, fixedInEntry.VulnerableRange, fixedInEntry.VersionFormat, vuln.Vulnerability.Name),
				},
				Fix: getFix(fixedInEntry),
			})
		}
		aph.BlobValue.Ranges = ranges
		afs = append(afs, aph)
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(afs))

	return afs
}

func getFix(fixedInEntry unmarshal.OSFixedIn) *grypeDB.Fix {
	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Version)

	fixState := grypeDB.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = grypeDB.FixedStatus
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = grypeDB.WontFixStatus
	}

	var linkOrder []string
	linkSet := strset.New()
	for _, a := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		if a.Link != "" && !linkSet.Has(a.Link) {
			linkOrder = append(linkOrder, a.Link)
			linkSet.Add(a.Link)
		}
	}

	var refs []grypeDB.Reference
	for _, l := range linkOrder {
		refs = append(refs, grypeDB.Reference{
			Tags: []string{grypeDB.AdvisoryReferenceTag},
			URL:  l,
		})
	}

	var detail *grypeDB.FixDetail
	if len(refs) > 0 {
		detail = &grypeDB.FixDetail{
			References: refs,
		}
	}

	return &grypeDB.Fix{
		Version: fixedInVersion,
		State:   fixState,
		Detail:  detail,
	}
}

func enforceConstraint(fixedVersion, vulnerableRange, format, vulnerabilityID string) string {
	if len(vulnerableRange) > 0 {
		return vulnerableRange
	}
	fixedVersion = common.CleanConstraint(fixedVersion)
	if len(fixedVersion) == 0 {
		return ""
	}
	switch strings.ToLower(format) {
	case "semver":
		return common.EnforceSemVerConstraint(fixedVersion)
	default:
		// the passed constraint is a fixed version
		return deriveConstraintFromFix(fixedVersion, vulnerabilityID)
	}
}

func deriveConstraintFromFix(fixVersion, vulnerabilityID string) string {
	constraint := fmt.Sprintf("< %s", fixVersion)

	if strings.HasPrefix(vulnerabilityID, "ALASKERNEL-") {
		// Amazon advisories of the form ALASKERNEL-5.4-2023-048 should be interpreted as only applying to
		// the 5.4.x kernel line since Amazon issue a separate advisory per affected line, thus the constraint
		// should be >= 5.4, < {fix version}.  In the future the vunnel schema for OS vulns should be enhanced
		// to emit actual constraints rather than fixed-in entries (tracked in https://github.com/anchore/vunnel/issues/266)
		// at which point this workaround in grype-db can be removed.

		components := strings.Split(vulnerabilityID, "-")

		if len(components) == 4 {
			base := components[1]
			constraint = fmt.Sprintf(">= %s, < %s", base, fixVersion)
		}
	}

	return constraint
}

type groupIndex struct {
	name      string
	osName    string
	osVersion string
	module    string
}

func groupFixedIns(vuln unmarshal.OSVulnerability) map[groupIndex][]unmarshal.OSFixedIn {
	grouped := make(map[groupIndex][]unmarshal.OSFixedIn)
	osName, osVersion := getOSInfo(vuln.Vulnerability.NamespaceName)

	for _, fixedIn := range vuln.Vulnerability.FixedIn {
		var mod string
		if fixedIn.Module != nil {
			mod = *fixedIn.Module
		}
		g := groupIndex{
			name:      fixedIn.Name,
			osName:    osName,
			osVersion: osVersion,
			module:    mod,
		}

		grouped[g] = append(grouped[g], fixedIn)
	}
	return grouped
}

func getPackageType(osName string) string {
	switch osName {
	case "redhat", "amazon", "oracle", "sles", "mariner", "azurelinux":
		return string(pkg.RpmPkg)
	case "ubuntu", "debian":
		return string(pkg.DebPkg)
	case "alpine", "chainguard", "wolfi":
		return string(pkg.ApkPkg)
	case "windows":
		return "msrc-kb"
	}

	return ""
}

func getPackage(group groupIndex) *grypeDB.Package {
	return &grypeDB.Package{
		Type: getPackageType(group.osName),
		Name: group.name,
	}
}

func getOSInfo(group string) (string, string) {
	// derived from enterprise feed groups, expected to be of the form {distroID}:{version}
	feedGroupComponents := strings.Split(group, ":")

	return normalizeOsName(feedGroupComponents[0], feedGroupComponents[1]), feedGroupComponents[1]
}

// add new fields to OS schema: release-id, release-version-id
// update vunnel providers to emit these fields (they are based on the /etc/os-release values)
// update this code to STOP parsing namespace and start using those new fields
// now when a user searches by OS (from the /etc/os-release values) they will get the correct results
// what's missing:
//   - when to search by major version vs major.minor version...
//   - edge/rolling behavior
//   - aliases: user has centos 8, but the feed has rhel 8, use that instead
func normalizeOsName(name, version string) string {
	if strings.ToLower(name) == "mariner" {
		verFields := strings.Split(version, ".")
		majorVersionStr := verFields[0]
		majorVer, err := strconv.Atoi(majorVersionStr)
		if err == nil {
			if majorVer >= 3 {
				name = string(distro.Azure)
			}
		}
	}
	d, ok := distro.IDMapping[name]
	if !ok {
		log.WithFields("distro", name).Warn("unknown distro name")

		return name
	}

	distroName := d.String()

	// TODO: this doesn't seem right
	switch d {
	case distro.OracleLinux:
		distroName = "oracle"
	case distro.AmazonLinux:
		distroName = "amazon"
	}
	return distroName
}

func getOperatingSystem(osName, osVersion string) *grypeDB.OperatingSystem {
	if osName == "" || osVersion == "" {
		return nil
	}

	versionFields := strings.Split(osVersion, ".")
	var majorVersion, minorVersion string
	majorVersion = versionFields[0]
	if len(versionFields) > 1 {
		minorVersion = versionFields[1]
	}

	return &grypeDB.OperatingSystem{
		Name:         osName,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		Codename:     codename.LookupOS(osName, majorVersion, minorVersion),
	}
}

func getReferences(vuln unmarshal.OSVulnerability) []grypeDB.Reference {
	clean := strings.TrimSpace(vuln.Vulnerability.Link)
	if clean == "" {
		return nil
	}

	var linkOrder []string
	linkSet := strset.New()
	if vuln.Vulnerability.Link != "" {
		linkSet.Add(vuln.Vulnerability.Link)
		linkOrder = append(linkOrder, vuln.Vulnerability.Link)
	}
	for _, a := range vuln.Vulnerability.Metadata.CVE {
		if a.Link != "" && !linkSet.Has(a.Link) {
			linkOrder = append(linkOrder, a.Link)
		}
	}

	var refs []grypeDB.Reference
	for _, l := range linkOrder {
		refs = append(refs,
			grypeDB.Reference{
				Tags: []string{grypeDB.AdvisoryReferenceTag},
				URL:  l,
			},
		)
	}

	return refs
}

func getAliases(vuln unmarshal.OSVulnerability) []string {
	var aliases []string
	for _, cve := range vuln.Vulnerability.Metadata.CVE {
		aliases = append(aliases,
			cve.Name,
		)
	}
	return aliases
}

func getSeverities(vuln unmarshal.OSVulnerability) []grypeDB.Severity {
	var severities []grypeDB.Severity

	// TODO: should we clean this here or not?
	if vuln.Vulnerability.Severity != "" && strings.ToLower(vuln.Vulnerability.Severity) != "unknown" {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCHMLN,
			Value:  strings.ToLower(vuln.Vulnerability.Severity),
			Rank:   1, // TODO: enum this
			// TODO Source?
		})
	}
	for _, vendorSeverity := range vuln.Vulnerability.CVSS {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCVSS,
			Value: grypeDB.CVSSSeverity{
				Vector:  vendorSeverity.VectorString,
				Version: vendorSeverity.Version,
				Score:   vendorSeverity.BaseMetrics.BaseScore,
			},
			Rank: 2,
			// TODO: source?
		})
	}

	return severities
}
