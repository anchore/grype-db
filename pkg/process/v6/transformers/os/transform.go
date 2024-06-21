package os

import (
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
		DetailDigest: strRef(descriptionDigest), // TODO: need access to digest store too
		References:   getReferences(vulnerability),
		Related:      nil, // TODO: find examples for this... odds are aliases is what we want most of the time
		Aliases:      getAliases(vulnerability),
		Severities:   getSeverities(vulnerability),
		//DbSpecificNvd: nil, // TODO: N/A for OS, are the others we should be considering though per distro?
		Affected: getAffecteds(vulnerability),
	}

	return transformers.NewEntries(vuln, blobs...), nil
}

func strRef(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func getAffecteds(vuln unmarshal.OSVulnerability) *[]grypeDB.Affected {
	var afs []grypeDB.Affected
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		// TODO: add purls!
		afs = append(afs, grypeDB.Affected{
			Packages: getPackages(group),
			//AffectedCpe:       getAffectedCPE(af), // TODO: this might not need to be done? unsure...
			//Versions:          getAffectedVersions(af), // TODO: do this later... there is no upstream support for this...
			//ExcludeVersions:   nil, // TODO...
			//Severities:        getAffectedSeverities(af) // TODO: this should be EMPTY if a top level severity exists (which is might)
			Range: getRange(fixedIns),
			//Digests:           nil, // TODO...

			OperatingSystem: getOperatingSystem(group.osName, group.osVersion),
			//PackageQualifierPlatformCpes:   nil, // TODO...
			PackageQualifierRpmModularities: getPackageQualifierRPMModularity(group.module),
		})
	}
	return &afs
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

func getRange(fixedIns []unmarshal.OSFixedIn) *[]grypeDB.Range {
	// TODO: do we ever know about multiple ranges?
	return &[]grypeDB.Range{
		{
			Type: "SEMVER", // TODO: enum
			//Repo:   "", // TODO
			Events: getRangeEvents(fixedIns),
		},
	}
}

func getRangeEvents(fixedIns []unmarshal.OSFixedIn) *[]grypeDB.RangeEvent {
	var rangeEvents []grypeDB.RangeEvent
	for _, fixedInEntry := range fixedIns {

		var fixedInVersions []string
		fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Version)
		if fixedInVersion != "" {
			fixedInVersions = append(fixedInVersions, fixedInVersion)
		}

		fixState := "not fixed" // TODO enum this
		if len(fixedInVersions) > 0 {
			fixState = "fixed" // TODO enum this
		} else if fixedInEntry.VendorAdvisory.NoAdvisory {
			fixState = "wont fix" // TODO enum this
		}

		// TODO: this topology seems problematic
		for _, ver := range fixedInVersions {
			rangeEvents = append(rangeEvents, grypeDB.RangeEvent{
				//Type:       "", // TODO
				//Repo:       "", // TODO
				Introduced: strPtr("0"),
				Fixed:      &ver,
				//LastAffected: "",  // TODO
				//Limit:        "",  // TODO
				State: fixState, // TODO: enum this relative to OSV
			})
		}
	}
	return &rangeEvents
}

func strPtr(s string) *string {
	return &s
}

func getPackages(group groupIndex) *[]grypeDB.Package {
	return &[]grypeDB.Package{
		{
			Ecosystem:   strPtr(normalizeOsName(group.osName)), // TODO: is this correct?
			PackageName: group.name,
		},
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

func getPackageQualifierRPMModularity(module string) *[]grypeDB.PackageQualifierRpmModularity {
	// TODO convert to single when model is updated
	if module == "" {
		return nil
	}
	return &[]grypeDB.PackageQualifierRpmModularity{
		{
			Module: module,
		},
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
			Type:     "string", // TODO: where should we get these values for each source?
			Score:    vuln.Vulnerability.Severity,
			Priority: strPtr("primary"), // TODO: enum this
			// TODO Source?
		})
	}
	for _, vendorSeverity := range vuln.Vulnerability.CVSS {
		severities = append(severities, grypeDB.Severity{
			Type:     "CVSS",                      // TODO: add version to this (different field already)
			Score:    vendorSeverity.VectorString, // TODO: this isn't really the score... this is a little odd
			Priority: strPtr("secondary"),         // TODO: I don't think this is always true
			// TODO: source?
		})
	}
	return &severities
}
