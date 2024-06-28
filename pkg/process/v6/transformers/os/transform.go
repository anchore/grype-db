package os

import (
	"fmt"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"strings"
)

func Transform(vulnerability unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	var blobs []grypeDB.Blob

	cleanDescription := strings.TrimSpace(vulnerability.Vulnerability.Description)
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
		Name: vulnerability.Vulnerability.Name,
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

	return transformers.NewEntries(vuln, blobs...), nil
}

func getAffecteds(vuln unmarshal.OSVulnerability) *[]grypeDB.Affected {
	var afs []grypeDB.Affected
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		// TODO: add purls!
		for idx, fixedInEntry := range fixedIns {
			afs = append(afs, grypeDB.Affected{
				Package:           getPackage(group),
				VersionConstraint: enforceConstraint(fixedInEntry.Version, fixedInEntry.VulnerableRange, fixedInEntry.VersionFormat, vuln.Vulnerability.Name),
				VersionFormat:     fixedInEntry.VersionFormat,
				OperatingSystem:   getOperatingSystem(group.osName, group.osVersion),
				RpmModularity:     group.module,
				Fix:               getFix(vuln, idx),
			})
		}

	}
	return &afs
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

func getPackage(group groupIndex) *grypeDB.Package {
	return &grypeDB.Package{
		Type: normalizeOsName(group.osName), // TODO: is this correct?
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

func getReferences(vuln unmarshal.OSVulnerability) *[]grypeDB.Reference {
	// TODO: should we collect entries from the fixed ins? or should there be references for affected (an OSV difference)
	return &[]grypeDB.Reference{
		{
			Type: "", // TODO: what's the right value here?
			URL:  vuln.Vulnerability.Link,
		},
	}
}

func getAliases(vuln unmarshal.OSVulnerability) *[]grypeDB.Alias {
	var aliases []grypeDB.Alias
	for _, cve := range vuln.Vulnerability.Metadata.CVE {
		aliases = append(aliases, grypeDB.Alias{
			// TODO: we're throwing away the link... should we put this in references?
			Alias: cve.Name,
		})
	}
	return &aliases
}

func getSeverities(vuln unmarshal.OSVulnerability) *[]grypeDB.Severity {
	var severities []grypeDB.Severity

	// TODO: should we clean this here or not?
	if vuln.Vulnerability.Severity != "" && strings.ToLower(vuln.Vulnerability.Severity) != "unknown" {
		severities = append(severities, grypeDB.Severity{
			Type:  "string", // TODO: where should we get these values for each source?
			Score: vuln.Vulnerability.Severity,
			Rank:  1, // TODO: enum this
			// TODO Source?
		})
	}
	for _, vendorSeverity := range vuln.Vulnerability.CVSS {
		severities = append(severities, grypeDB.Severity{
			Type:  "CVSS",                      // TODO: add version to this (different field already)
			Score: vendorSeverity.VectorString, // TODO: this isn't really the score... this is a little odd
			Rank:  2,                           // TODO: I don't think this is always true
			// TODO: source?
		})
	}

	return &severities
}
