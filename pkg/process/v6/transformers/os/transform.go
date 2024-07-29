package os

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
)

func Transform(vulnerability unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	in := []any{
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
			Name: vulnerability.Vulnerability.Name,
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:            vulnerability.Vulnerability.Name, // TODO: should we strip this and let a business object hold this?
				ProviderName:  state.Provider,
				Assigner:      nil,
				Description:   strings.TrimSpace(vulnerability.Vulnerability.Description),
				ModifiedDate:  nil, // TODO
				PublishedDate: nil, // TODO
				//WithdrawnDate: nil, // TODO
				Status:     "", // TODO
				References: getReferences(vulnerability),
				Aliases:    getAliases(vulnerability),
				Severities: getSeverities(vulnerability),
			},
		},
	}

	for _, a := range getAffecteds(vulnerability) {
		in = append(in, a)
	}

	return transformers.NewEntries(in...), nil
}

func getAffecteds(vuln unmarshal.OSVulnerability) []grypeDB.AffectedPackageHandle {
	var afs []grypeDB.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		aph := grypeDB.AffectedPackageHandle{
			VulnerabilityID: 0, // TODO: how are we correlating this?
			OperatingSystem: getOperatingSystem(group.osName, group.osVersion),
			Package:         getPackage(group),

			BlobValue: &grypeDB.AffectedBlob{
				CVEs:          getAliases(vuln),
				RpmModularity: group.module,

				Ranges: nil,
			},
		}

		var ranges []grypeDB.AffectedRange
		for idx, fixedInEntry := range fixedIns {
			ranges = append(ranges, grypeDB.AffectedRange{
				Version: grypeDB.AffectedVersion{
					Type:       fixedInEntry.VersionFormat,
					Constraint: enforceConstraint(fixedInEntry.Version, fixedInEntry.VulnerableRange, fixedInEntry.VersionFormat, vuln.Vulnerability.Name),
				},
				Fix: getFix(vuln, idx),
			})
		}
		aph.BlobValue.Ranges = ranges
		afs = append(afs, aph)
	}
	return afs
}

func getFix(entry unmarshal.OSVulnerability, idx int) *grypeDB.Fix {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Version)

	fixState := "not-fixed" // TODO enum
	if len(fixedInVersion) > 0 {
		fixState = "fixed" // TODO enum
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = "wont-fix" // TODO: enum
	}

	return &grypeDB.Fix{
		Version: fixedInVersion,
		State:   fixState,
		// TODO: detail
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
	case "redhat", "amazon", "oracle", "sles", "mariner":
		return "rpm"
	case "ubuntu", "debian":
		return "deb"
	case "alpine", "chainguard", "wolfi":
		return "apk"
	case "windows":
		return "msrc-kb"
	}

	return ""
}

func getPackage(group groupIndex) *grypeDB.Package {
	return &grypeDB.Package{
		Type: getPackageType(group.osName), // TODO: is this correct?
		Name: group.name,
	}
}

func getOSInfo(group string) (string, string) {
	// Currently known enterprise feed groups are expected to be of the form {distroID}:{version}
	feedGroupComponents := strings.Split(group, ":")

	return normalizeOsName(feedGroupComponents[0]), feedGroupComponents[1]
}

func normalizeOsName(name string) string {
	d, ok := distro.IDMapping[name]
	if !ok {
		// TODO: log error? return error?

		return name
	}

	distroName := d.String()

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
		Codename:     "", // TODO: fill this in from somewhere?
	}
}

func getReferences(vuln unmarshal.OSVulnerability) []grypeDB.Reference {
	// TODO: should we collect entries from the fixed ins? or should there be references for affected (an OSV difference)

	clean := strings.TrimSpace(vuln.Vulnerability.Link)
	if clean == "" {
		return nil
	}

	return []grypeDB.Reference{
		{
			Tags: nil, // TODO: what's the right value here?
			URL:  vuln.Vulnerability.Link,
		},
	}
}

func getAliases(vuln unmarshal.OSVulnerability) []string {
	var aliases []string
	for _, cve := range vuln.Vulnerability.Metadata.CVE {
		aliases = append(aliases,
			// TODO: we're throwing away the link... should we put this in references?
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
			Scheme: grypeDB.SeveritySchemeCHMLN, // TODO: where should we get these values for each source?
			Value:  vuln.Vulnerability.Severity,
			Rank:   1, // TODO: enum this
			// TODO Source?
		})
	}
	for _, vendorSeverity := range vuln.Vulnerability.CVSS {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCVSSV2, // TODO: is this always v2? or should we detect based off the vector?
			Value:  vendorSeverity.VectorString,  // TODO: this isn't really the score... this is a little odd
			Rank:   2,                            // TODO: I don't think this is always true
			// TODO: source?
		})
	}

	return severities
}
