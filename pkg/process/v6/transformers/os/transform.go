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
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/pkg"
)

const (
	rootioNamespacePrefix = "rootio"
)

// advisoryKey is an internal struct used for sorting and deduplicating advisories
// that have both a link and ID from the vunnel results data
type advisoryKey struct {
	id   string
	link string
}

func Transform(vulnerability unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	if isRootIoNamespace(vulnerability.Vulnerability.NamespaceName) {
		return processRootIoVulnerability(vulnerability, state)
	}
	in := []any{
		grypeDB.VulnerabilityHandle{
			Name:          vulnerability.Vulnerability.Name,
			ProviderID:    state.Provider,
			Provider:      internal.ProviderModel(state),
			Status:        grypeDB.VulnerabilityActive,
			ModifiedDate:  internal.ParseTime(vulnerability.Vulnerability.Metadata.Updated),
			PublishedDate: internal.ParseTime(vulnerability.Vulnerability.Metadata.Issued),
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:          vulnerability.Vulnerability.Name,
				Assigners:   nil,
				Description: strings.TrimSpace(vulnerability.Vulnerability.Description),
				References:  getReferences(vulnerability),
				Aliases:     getAliases(vulnerability),
				Severities:  getSeverities(vulnerability),
			},
		},
	}

	for _, a := range getAffectedPackages(vulnerability) {
		in = append(in, a)
	}

	return transformers.NewEntries(in...), nil
}

func isRootIoNamespace(namespace string) bool {
	return strings.HasPrefix(namespace, rootioNamespacePrefix+":")
}

func processRootIoVulnerability(vuln unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	var entries []any

	entries = append(entries, grypeDB.VulnerabilityHandle{
		Name:          vuln.Vulnerability.Name,
		ProviderID:    state.Provider,
		Provider:      internal.ProviderModel(state),
		Status:        grypeDB.VulnerabilityActive,
		ModifiedDate:  internal.ParseTime(vuln.Vulnerability.Metadata.Updated),
		PublishedDate: internal.ParseTime(vuln.Vulnerability.Metadata.Issued),
		BlobValue: &grypeDB.VulnerabilityBlob{
			ID:          vuln.Vulnerability.Name,
			Assigners:   nil,
			Description: strings.TrimSpace(vuln.Vulnerability.Description),
			References:  getReferences(vuln),
			Aliases:     getAliases(vuln),
			Severities:  getSeverities(vuln),
		},
	})

	for _, u := range getRootIoUnaffectedPackages(vuln) {
		entries = append(entries, u)
	}

	return transformers.NewEntries(entries...), nil
}

func getRootIoUnaffectedPackages(vuln unmarshal.OSVulnerability) []grypeDB.UnaffectedPackageHandle {
	var uphs []grypeDB.UnaffectedPackageHandle
	groups := groupFixedIns(vuln)

	for group, fixedIns := range groups {
		for _, fixedIn := range fixedIns {
			if fixedIn.Version != "" {
				uph := grypeDB.UnaffectedPackageHandle{
					Package:         getPackage(group),
					OperatingSystem: getOperatingSystem(group.osName, group.id, group.osVersion, group.osChannel),
					BlobValue:       getRootIoUnaffectedBlob(vuln, fixedIn, group),
				}
				uphs = append(uphs, uph)
				break
			}
		}
	}

	sort.Sort(internal.ByUnaffectedPackage(uphs))
	return uphs
}

func getRootIoUnaffectedBlob(vuln unmarshal.OSVulnerability, fixedIn unmarshal.OSFixedIn, group groupIndex) *grypeDB.PackageBlob {
	cves := getAliases(vuln)

	constraint := determineRootIoConstraint(group.osName, fixedIn.Version)
	ranges := []grypeDB.Range{
		{
			Version: grypeDB.Version{
				Type:       fixedIn.VersionFormat,
				Constraint: constraint,
			},
		},
	}

	return &grypeDB.PackageBlob{
		CVEs:   cves,
		Ranges: ranges,
	}
}

func determineRootIoConstraint(osName string, version string) string {
	switch osName {
	case "debian", "ubuntu":
		// Debian/Ubuntu packages use .root.io suffix
		// Example: 1.5.2-6+deb12u1.root.io.4
		return "version_contains .root.io"
	case "alpine", "chainguard", "wolfi":
		// Alpine packages may use either:
		// 1. .root.io suffix (e.g., 3.0.8-r3.root.io.1)
		// 2. -rXX007X pattern (e.g., 3.0.8-r00071, 3.0.8-r10074)
		// We check for .root.io first as it's more common across distros
		// The -rXX007X pattern check is handled in Grype's IsRootIoPackage()
		return "version_contains .root.io"
	default:
		return "version_contains .root.io"
	}
}

func getAffectedPackages(vuln unmarshal.OSVulnerability) []grypeDB.AffectedPackageHandle {
	var afs []grypeDB.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		// we only care about a single qualifier: rpm modules. The important thing to note about this is that
		// a package with no module vs a package with a module should be detectable in the DB.
		var qualifiers *grypeDB.PackageQualifiers
		if group.format == "rpm" {
			module := "" // means the target package must have no module (where as nil means the module has no sway on matching)
			if group.hasModule {
				module = group.module
			}
			qualifiers = &grypeDB.PackageQualifiers{
				RpmModularity: &module,
			}
		}

		aph := grypeDB.AffectedPackageHandle{
			OperatingSystem: getOperatingSystem(group.osName, group.id, group.osVersion, group.osChannel),
			Package:         getPackage(group),
			BlobValue: &grypeDB.PackageBlob{
				CVEs:       getAliases(vuln),
				Qualifiers: qualifiers,
				Ranges:     nil,
			},
		}

		var ranges []grypeDB.Range
		for _, fixedInEntry := range fixedIns {
			ranges = append(ranges, grypeDB.Range{
				Version: grypeDB.Version{
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

	var advisoryOrder []advisoryKey
	advisorySet := strset.New()
	for _, a := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		if a.Link != "" && !advisorySet.Has(a.Link) {
			advisoryOrder = append(advisoryOrder, advisoryKey{id: a.ID, link: a.Link})
			advisorySet.Add(a.Link)
		}
	}

	var refs []grypeDB.Reference
	for _, adv := range advisoryOrder {
		refs = append(refs, grypeDB.Reference{
			ID:   adv.id,
			URL:  adv.link,
			Tags: []string{grypeDB.AdvisoryReferenceTag},
		})
	}

	var detail *grypeDB.FixDetail
	availability := getFixAvailability(fixedInEntry)
	if len(refs) > 0 || availability != nil {
		detail = &grypeDB.FixDetail{
			Available:  availability,
			References: refs,
		}
	}

	return &grypeDB.Fix{
		Version: fixedInVersion,
		State:   fixState,
		Detail:  detail,
	}
}

func getFixAvailability(fixedInEntry unmarshal.OSFixedIn) *grypeDB.FixAvailability {
	if fixedInEntry.Available.Date == "" {
		return nil
	}

	t := internal.ParseTime(fixedInEntry.Available.Date)
	if t == nil {
		log.WithFields("date", fixedInEntry.Available.Date).Warn("unable to parse fix availability date")
		return nil
	}

	return &grypeDB.FixAvailability{
		Date: t,
		Kind: fixedInEntry.Available.Kind,
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
	id        string
	osName    string
	osVersion string
	osChannel string
	hasModule bool
	module    string
	format    string
}

func groupFixedIns(vuln unmarshal.OSVulnerability) map[groupIndex][]unmarshal.OSFixedIn {
	grouped := make(map[groupIndex][]unmarshal.OSFixedIn)
	oi := getOSInfo(vuln.Vulnerability.NamespaceName)

	for _, fixedIn := range vuln.Vulnerability.FixedIn {
		var mod string
		if fixedIn.Module != nil {
			mod = *fixedIn.Module
		}
		g := groupIndex{
			name:      fixedIn.Name,
			id:        oi.id,
			osName:    oi.name,
			osVersion: oi.version,
			osChannel: oi.channel,
			hasModule: fixedIn.Module != nil,
			module:    mod,
			format:    fixedIn.VersionFormat,
		}

		grouped[g] = append(grouped[g], fixedIn)
	}
	return grouped
}

func getPackageType(osName string) pkg.Type {
	switch osName {
	case "redhat", "amazonlinux", "oraclelinux", "sles", "mariner", "azurelinux":
		return pkg.RpmPkg
	case "ubuntu", "debian", "echo":
		return pkg.DebPkg
	case "alpine", "chainguard", "wolfi", "minimos":
		return pkg.ApkPkg
	case "windows":
		return pkg.KbPkg
	}

	return ""
}

func getPackage(group groupIndex) *grypeDB.Package {
	t := getPackageType(group.osName)
	return &grypeDB.Package{
		Ecosystem: string(t),
		Name:      name.Normalize(group.name, t),
	}
}

type osInfo struct {
	name    string
	id      string
	version string
	channel string
}

func getOSInfo(group string) osInfo {
	// derived from enterprise feed groups, expected to be of the form {distro release ID}:{version}
	// or for Root.io: rootio:distro:{distro}:{version}
	feedGroupComponents := strings.Split(group, ":")

	// Handle Root.io namespace format
	if len(feedGroupComponents) >= 4 && feedGroupComponents[0] == rootioNamespacePrefix && feedGroupComponents[1] == "distro" {
		// Root.io format: rootio:distro:alpine:3.17
		id := feedGroupComponents[2]
		version := feedGroupComponents[3]
		return osInfo{
			name:    normalizeOsName(id),
			id:      rootioNamespacePrefix + "-" + id, // Prefix with rootio to distinguish
			version: version,
			channel: "",
		}
	}

	id := feedGroupComponents[0]
	version := feedGroupComponents[1]
	channel := ""
	if strings.Contains(feedGroupComponents[1], "+") {
		versionParts := strings.Split(feedGroupComponents[1], "+")
		channel = versionParts[1]
		version = versionParts[0]
	}
	if strings.ToLower(id) == "mariner" {
		verFields := strings.Split(version, ".")
		majorVersionStr := verFields[0]
		majorVer, err := strconv.Atoi(majorVersionStr)
		if err == nil {
			if majorVer >= 3 {
				id = string(distro.Azure)
			}
		}
	}

	return osInfo{
		name:    normalizeOsName(id),
		id:      id,
		version: version,
		channel: channel,
	}
}

func normalizeOsName(id string) string {
	d, ok := distro.IDMapping[id]
	if !ok {
		log.WithFields("distro", id).Warn("unknown distro name")

		return id
	}

	return d.String()
}

func getOperatingSystem(osName, osID, osVersion, channel string) *grypeDB.OperatingSystem {
	if osName == "" || osVersion == "" {
		return nil
	}

	versionFields := strings.Split(osVersion, ".")
	var majorVersion, minorVersion, labelVersion string
	majorVersion = versionFields[0]
	if len(majorVersion) > 0 {
		// is the first field a number?
		_, err := strconv.Atoi(majorVersion[0:1])
		if err != nil {
			labelVersion = majorVersion
			majorVersion = ""
		} else if len(versionFields) > 1 {
			minorVersion = versionFields[1]
		}
	}

	return &grypeDB.OperatingSystem{
		Name:         osName,
		ReleaseID:    osID,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		LabelVersion: labelVersion,
		Channel:      channel,
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
				URL: l,
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
			},
			Rank: 2,
			// TODO: source?
		})
	}

	return severities
}
