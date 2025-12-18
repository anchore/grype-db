package csafvex

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/umisama/go-cpe"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/codename"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(advisory unmarshal.CSAFVEXVulnerability, state provider.State) ([]data.Entry, error) {
	if advisory.Document == nil || advisory.Document.Tracking == nil {
		return nil, fmt.Errorf("invalid CSAF advisory: missing document or tracking information")
	}

	// Build a map of product ID to product info for lookups
	productMap := buildProductMap(advisory.ProductTree)

	var allEntries []data.Entry

	for _, vuln := range advisory.Vulnerabilities {
		entries, err := transformVulnerability(advisory, vuln, productMap, state)
		if err != nil {
			return nil, fmt.Errorf("failed to transform vulnerability: %w", err)
		}
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

type productInfo struct {
	name    string
	version string
	purl    *packageurl.PackageURL
	os      *grypeDB.OperatingSystem
}

func buildProductMap(tree *csaf.ProductTree) map[csaf.ProductID]productInfo {
	products := make(map[csaf.ProductID]productInfo)
	if tree == nil {
		return products
	}

	// First pass: build a map of OS product IDs to their OS info (from CPE)
	osProducts := make(map[csaf.ProductID]*grypeDB.OperatingSystem)

	// Walk branches to find products and extract OS info from CPE
	var walkBranches func(branches csaf.Branches, parentName, parentVersion string)
	walkBranches = func(branches csaf.Branches, parentName, parentVersion string) {
		for _, branch := range branches {
			if branch == nil {
				continue
			}

			name := parentName
			version := parentVersion

			if branch.Category != nil {
				switch *branch.Category {
				case csaf.CSAFBranchCategoryProductName:
					if branch.Name != nil {
						name = *branch.Name
					}
				case csaf.CSAFBranchCategoryProductVersion:
					if branch.Name != nil {
						version = *branch.Name
					}
				}
			}

			// If this branch has a product, record it
			if branch.Product != nil && branch.Product.ProductID != nil {
				info := productInfo{
					name:    name,
					version: version,
				}

				// Extract PURL if available
				if branch.Product.ProductIdentificationHelper != nil &&
					branch.Product.ProductIdentificationHelper.PURL != nil {
					purlStr := string(*branch.Product.ProductIdentificationHelper.PURL)
					if p, err := packageurl.FromString(purlStr); err == nil {
						info.purl = &p
						// Use PURL name/version if available
						if p.Name != "" {
							info.name = p.Name
						}
						if p.Version != "" {
							info.version = p.Version
						}
					}
				}

				// Check if this is an OS product (has CPE with type 'o' for operating system)
				if branch.Product.ProductIdentificationHelper != nil &&
					branch.Product.ProductIdentificationHelper.CPE != nil {
					cpeStr := string(*branch.Product.ProductIdentificationHelper.CPE)
					if os := parseOSFromCPE(cpeStr); os != nil {
						osProducts[*branch.Product.ProductID] = os
					}
				}

				products[*branch.Product.ProductID] = info
			}

			// Recurse into child branches
			if len(branch.Branches) > 0 {
				walkBranches(branch.Branches, name, version)
			}
		}
	}

	walkBranches(tree.Branches, "", "")

	// Also handle full_product_names at root level
	if tree.FullProductNames != nil {
		for _, fpn := range *tree.FullProductNames {
			if fpn == nil || fpn.ProductID == nil {
				continue
			}
			info := productInfo{}
			if fpn.Name != nil {
				info.name = *fpn.Name
			}
			if fpn.ProductIdentificationHelper != nil &&
				fpn.ProductIdentificationHelper.PURL != nil {
				purlStr := string(*fpn.ProductIdentificationHelper.PURL)
				if p, err := packageurl.FromString(purlStr); err == nil {
					info.purl = &p
					if p.Name != "" {
						info.name = p.Name
					}
					if p.Version != "" {
						info.version = p.Version
					}
				}
			}
			// Check for OS CPE
			if fpn.ProductIdentificationHelper != nil &&
				fpn.ProductIdentificationHelper.CPE != nil {
				cpeStr := string(*fpn.ProductIdentificationHelper.CPE)
				if os := parseOSFromCPE(cpeStr); os != nil {
					osProducts[*fpn.ProductID] = os
				}
			}
			products[*fpn.ProductID] = info
		}
	}

	// Second pass: process relationships to link composite product IDs to their OS
	// Relationships map package products to OS products via relates_to_product_reference
	// The product_reference is typically an RPM NEVRA string like "libfoo-1.2.3-4.5.1"
	if tree.RelationShips != nil {
		for _, rel := range *tree.RelationShips {
			if rel == nil || rel.FullProductName == nil || rel.FullProductName.ProductID == nil {
				continue
			}
			if rel.RelatesToProductReference == nil {
				continue
			}

			compositeProductID := *rel.FullProductName.ProductID
			osProductID := csaf.ProductID(*rel.RelatesToProductReference)

			// Look up the OS info for this relationship
			if os, ok := osProducts[osProductID]; ok {
				// Get or create the product info for the composite ID
				info := products[compositeProductID]
				info.os = os

				// If the composite product doesn't have package info yet,
				// parse it from the product_reference (RPM NEVRA string)
				if info.name == "" && rel.ProductReference != nil {
					pkgRef := string(*rel.ProductReference)
					// First try to look it up as a product ID
					pkgProductID := csaf.ProductID(pkgRef)
					if pkgInfo, ok := products[pkgProductID]; ok && pkgInfo.name != "" {
						info.name = pkgInfo.name
						info.version = pkgInfo.version
						info.purl = pkgInfo.purl
					} else {
						// Parse RPM NEVRA string: name-version-release.arch or name-version-release
						// Examples: "cpio-2.12-3.9.1", "libjavascriptcoregtk-4_0-18-2.24.2-3.27.1"
						name, version := parseRPMNameVersion(pkgRef)
						info.name = name
						info.version = version
					}
				}

				products[compositeProductID] = info
			}
		}
	}

	return products
}

// parseRPMNameVersion extracts the package name and version from an RPM NEVRA-like string.
// RPM naming: name-version-release or name-version-release.arch
// Examples:
//   - "cpio-2.12-3.9.1" -> name="cpio", version="2.12-3.9.1"
//   - "libjavascriptcoregtk-4_0-18-2.24.2-3.27.1" -> name="libjavascriptcoregtk-4_0-18", version="2.24.2-3.27.1"
//
// The challenge is that package names can contain hyphens. We look for the pattern where
// a hyphen is followed by a digit, which typically marks the start of the version.
func parseRPMNameVersion(nevra string) (name, version string) {
	if nevra == "" {
		return "", ""
	}

	// Find the last hyphen followed by a digit - this marks the release portion
	// Then find the second-to-last such pattern for the version
	// Pattern: name-version-release where version starts with a digit

	lastVersionIdx := -1
	for i := len(nevra) - 1; i > 0; i-- {
		if nevra[i-1] == '-' && i < len(nevra) && nevra[i] >= '0' && nevra[i] <= '9' {
			if lastVersionIdx == -1 {
				lastVersionIdx = i - 1 // This is the release separator
			} else {
				// This is the version separator
				return nevra[:i-1], nevra[i:]
			}
		}
	}

	// If we only found one separator, split there
	if lastVersionIdx > 0 {
		return nevra[:lastVersionIdx], nevra[lastVersionIdx+1:]
	}

	// No version found, return the whole string as name
	return nevra, ""
}

// parseOSFromCPE extracts operating system information from a CPE string.
// Supports both CPE 2.2 (cpe:/o:vendor:product:version) and CPE 2.3 (cpe:2.3:o:vendor:product:version:...) formats.
func parseOSFromCPE(cpeStr string) *grypeDB.OperatingSystem {
	if cpeStr == "" {
		return nil
	}

	var product, version, update string

	// Try CPE 2.3 format first using the go-cpe library
	if strings.HasPrefix(cpeStr, "cpe:2.3:") {
		c, err := cpe.NewItemFromFormattedString(cpeStr)
		if err != nil {
			return nil
		}
		// Only process operating system CPEs (part 'o')
		if string(c.Part()) != "o" {
			return nil
		}
		product = c.Product().String()
		version = c.Version().String()
		update = c.Update().String()
	} else if strings.HasPrefix(cpeStr, "cpe:/") {
		// CPE 2.2 format: cpe:/part:vendor:product:version:update:...
		// Example: cpe:/o:suse:sles:15:sp1
		remainder := strings.TrimPrefix(cpeStr, "cpe:/")
		parts := strings.Split(remainder, ":")
		if len(parts) < 1 || parts[0] != "o" {
			return nil // not an OS CPE
		}
		// parts[0] = part (o)
		// parts[1] = vendor (suse)
		// parts[2] = product (sles)
		// parts[3] = version (15)
		// parts[4] = update (sp1)
		if len(parts) >= 3 {
			product = parts[2]
		}
		if len(parts) >= 4 {
			version = parts[3]
		}
		if len(parts) >= 5 {
			update = parts[4]
		}
	} else {
		return nil
	}

	// Skip wildcard or NA values
	if version == "*" || version == "-" {
		version = ""
	}
	if update == "*" || update == "-" {
		update = ""
	}

	// Map SUSE product codes to distro IDs
	releaseID := normalizeReleaseID(product)

	// Parse version and update (service pack) into major/minor
	majorVersion, minorVersion := parseVersionComponents(version, update)

	// Get the normalized OS name using grype's distro mapping
	osName := normalizeOsName(releaseID)

	if osName == "" && releaseID == "" {
		return nil
	}

	return &grypeDB.OperatingSystem{
		Name:         osName,
		ReleaseID:    releaseID,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		Codename:     codename.LookupOS(osName, majorVersion, minorVersion),
	}
}

// normalizeReleaseID maps SUSE product codes to standard distro release IDs
func normalizeReleaseID(product string) string {
	product = strings.ToLower(product)

	// Handle hyphenated and underscored SLES variants
	// e.g., sles-bcl, sles-ltss, sles-espos, suse_sles, sles_sap, sles_bcl
	if strings.HasPrefix(product, "sles-") || strings.HasPrefix(product, "sles_") {
		return "sles"
	}
	if strings.HasPrefix(product, "suse_sles") || strings.HasPrefix(product, "suse-sles") {
		return "sles"
	}
	if strings.HasPrefix(product, "sle-") || strings.HasPrefix(product, "sle_") {
		return "sles"
	}

	switch product {
	case "sled", "sles", "sle_hpc", "sle-module-basesystem", "sle-module-server-applications":
		return "sles"
	case "caasp":
		return "sles" // SUSE CaaS Platform is based on SLES
	case "ses":
		return "sles" // SUSE Enterprise Storage is based on SLES
	case "sll":
		return "sles" // SUSE Liberty Linux
	case "opensuse", "leap", "opensuse-leap":
		return "opensuse-leap"
	case "tumbleweed", "opensuse-tumbleweed":
		return "opensuse-tumbleweed"
	default:
		return product
	}
}

// normalizeOsName uses grype's distro mapping to get the canonical OS name
func normalizeOsName(releaseID string) string {
	d, ok := distro.IDMapping[releaseID]
	if !ok {
		return releaseID
	}
	return d.String()
}

// parseVersionComponents extracts major and minor version from version string and update/service pack
func parseVersionComponents(version, update string) (major, minor string) {
	if version == "" {
		return "", ""
	}

	// Handle versions like "15" or "15.1"
	versionParts := strings.Split(version, ".")
	major = versionParts[0]

	if len(versionParts) > 1 {
		minor = versionParts[1]
	}

	// If there's an update/service pack (e.g., "sp2", "sp3"), extract the number as minor version
	if update != "" && minor == "" {
		// Match patterns like "sp2", "SP3", etc.
		spPattern := regexp.MustCompile(`(?i)^sp(\d+)$`)
		if matches := spPattern.FindStringSubmatch(update); len(matches) == 2 {
			minor = matches[1]
		}
	}

	return major, minor
}

func transformVulnerability(advisory unmarshal.CSAFVEXVulnerability, vuln *csaf.Vulnerability, productMap map[csaf.ProductID]productInfo, state provider.State) ([]data.Entry, error) {
	if vuln == nil {
		return nil, nil
	}

	vulnID := getVulnerabilityID(advisory, vuln)
	if vulnID == "" {
		return nil, fmt.Errorf("vulnerability has no ID")
	}

	vulnHandle := grypeDB.VulnerabilityHandle{
		Name:          vulnID,
		ProviderID:    state.Provider,
		Provider:      internal.ProviderModel(state),
		Status:        grypeDB.VulnerabilityActive,
		PublishedDate: internal.ParseTime(getInitialReleaseDate(advisory)),
		ModifiedDate:  internal.ParseTime(getCurrentReleaseDate(advisory)),
		BlobValue: &grypeDB.VulnerabilityBlob{
			ID:          vulnID,
			Description: getDescription(vuln),
			References:  getReferences(advisory, vuln),
			Aliases:     getAliases(vuln),
			Severities:  getSeverities(vuln),
		},
	}

	in := []any{vulnHandle}

	// Get affected packages from product_status
	aphs := getAffectedPackages(vuln, productMap, vulnID)
	for _, aph := range aphs {
		in = append(in, aph)
	}

	return transformers.NewEntries(in...), nil
}

func getVulnerabilityID(advisory unmarshal.CSAFVEXVulnerability, vuln *csaf.Vulnerability) string {
	// Prefer CVE if available
	if vuln.CVE != nil && *vuln.CVE != "" {
		return string(*vuln.CVE)
	}

	// Fall back to tracking ID
	if advisory.Document != nil && advisory.Document.Tracking != nil &&
		advisory.Document.Tracking.ID != nil {
		return string(*advisory.Document.Tracking.ID)
	}

	return ""
}

func getInitialReleaseDate(advisory unmarshal.CSAFVEXVulnerability) string {
	if advisory.Document != nil && advisory.Document.Tracking != nil &&
		advisory.Document.Tracking.InitialReleaseDate != nil {
		return *advisory.Document.Tracking.InitialReleaseDate
	}
	return ""
}

func getCurrentReleaseDate(advisory unmarshal.CSAFVEXVulnerability) string {
	if advisory.Document != nil && advisory.Document.Tracking != nil &&
		advisory.Document.Tracking.CurrentReleaseDate != nil {
		return *advisory.Document.Tracking.CurrentReleaseDate
	}
	return ""
}

func getDescription(vuln *csaf.Vulnerability) string {
	if vuln.Notes == nil {
		return ""
	}

	for _, note := range vuln.Notes {
		if note == nil || note.Text == nil {
			continue
		}
		// Prefer description or summary notes
		if note.NoteCategory != nil {
			cat := string(*note.NoteCategory)
			if cat == "description" || cat == "summary" {
				return *note.Text
			}
		}
	}

	// Fall back to first note
	for _, note := range vuln.Notes {
		if note != nil && note.Text != nil {
			return *note.Text
		}
	}

	return ""
}

func getReferences(advisory unmarshal.CSAFVEXVulnerability, vuln *csaf.Vulnerability) []grypeDB.Reference {
	var refs []grypeDB.Reference

	// Add document-level references
	if advisory.Document != nil && advisory.Document.References != nil {
		for _, ref := range advisory.Document.References {
			if ref == nil || ref.URL == nil {
				continue
			}
			refs = append(refs, grypeDB.Reference{
				URL: *ref.URL,
			})
		}
	}

	// Add vulnerability-level references
	if vuln.References != nil {
		for _, ref := range vuln.References {
			if ref == nil || ref.URL == nil {
				continue
			}
			refs = append(refs, grypeDB.Reference{
				URL: *ref.URL,
			})
		}
	}

	return refs
}

func getAliases(vuln *csaf.Vulnerability) []string {
	var aliases []string

	// Add CVE as alias if present
	if vuln.CVE != nil && *vuln.CVE != "" {
		aliases = append(aliases, string(*vuln.CVE))
	}

	// Add other IDs
	if vuln.IDs != nil {
		for _, id := range vuln.IDs {
			if id != nil && id.Text != nil {
				aliases = append(aliases, *id.Text)
			}
		}
	}

	return aliases
}

func getSeverities(vuln *csaf.Vulnerability) []grypeDB.Severity {
	var severities []grypeDB.Severity

	if vuln.Scores == nil {
		return severities
	}

	for _, score := range vuln.Scores {
		if score == nil {
			continue
		}

		if score.CVSS3 != nil && score.CVSS3.VectorString != nil {
			version := "3.1"
			if score.CVSS3.Version != nil {
				version = string(*score.CVSS3.Version)
			}
			severities = append(severities, grypeDB.Severity{
				Scheme: grypeDB.SeveritySchemeCVSS,
				Value: grypeDB.CVSSSeverity{
					Vector:  string(*score.CVSS3.VectorString),
					Version: version,
				},
			})
		}

		if score.CVSS2 != nil && score.CVSS2.VectorString != nil {
			severities = append(severities, grypeDB.Severity{
				Scheme: grypeDB.SeveritySchemeCVSS,
				Value: grypeDB.CVSSSeverity{
					Vector:  string(*score.CVSS2.VectorString),
					Version: "2.0",
				},
			})
		}
	}

	return severities
}

func getAffectedPackages(vuln *csaf.Vulnerability, productMap map[csaf.ProductID]productInfo, vulnID string) []grypeDB.AffectedPackageHandle {
	if vuln.ProductStatus == nil {
		return nil
	}

	var aphs []grypeDB.AffectedPackageHandle

	// Process known_affected products
	if vuln.ProductStatus.KnownAffected != nil {
		for _, productID := range *vuln.ProductStatus.KnownAffected {
			if productID == nil {
				continue
			}
			aph := createAffectedPackage(*productID, productMap, vuln, vulnID, grypeDB.NotFixedStatus)
			if aph != nil {
				aphs = append(aphs, *aph)
			}
		}
	}

	// Process fixed products
	if vuln.ProductStatus.Fixed != nil {
		for _, productID := range *vuln.ProductStatus.Fixed {
			if productID == nil {
				continue
			}
			aph := createAffectedPackage(*productID, productMap, vuln, vulnID, grypeDB.FixedStatus)
			if aph != nil {
				aphs = append(aphs, *aph)
			}
		}
	}

	// Process first_fixed products (first version that contains the fix)
	if vuln.ProductStatus.FirstFixed != nil {
		for _, productID := range *vuln.ProductStatus.FirstFixed {
			if productID == nil {
				continue
			}
			aph := createAffectedPackage(*productID, productMap, vuln, vulnID, grypeDB.FixedStatus)
			if aph != nil {
				aphs = append(aphs, *aph)
			}
		}
	}

	// Process recommended products (recommended remediation version)
	// These are treated as fixed versions since they represent the recommended fix
	if vuln.ProductStatus.Recommended != nil {
		for _, productID := range *vuln.ProductStatus.Recommended {
			if productID == nil {
				continue
			}
			aph := createAffectedPackage(*productID, productMap, vuln, vulnID, grypeDB.FixedStatus)
			if aph != nil {
				aphs = append(aphs, *aph)
			}
		}
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(aphs))

	return aphs
}

func createAffectedPackage(productID csaf.ProductID, productMap map[csaf.ProductID]productInfo, vuln *csaf.Vulnerability, vulnID string, fixStatus grypeDB.FixStatus) *grypeDB.AffectedPackageHandle {
	info, ok := productMap[productID]
	if !ok || info.name == "" {
		return nil
	}

	ecosystem := ""
	if info.purl != nil {
		ecosystem = string(pkg.TypeFromPURL(info.purl.String()))
	}

	grypePackage := &grypeDB.Package{
		Ecosystem: ecosystem,
		Name:      info.name,
	}

	// Build version constraint
	constraint := ""
	if info.version != "" {
		if fixStatus == grypeDB.FixedStatus {
			constraint = fmt.Sprintf("< %s", info.version)
		} else {
			constraint = fmt.Sprintf("= %s", info.version)
		}
	}

	var fix *grypeDB.Fix
	if fixStatus != "" {
		fix = &grypeDB.Fix{
			State: fixStatus,
		}
		if fixStatus == grypeDB.FixedStatus && info.version != "" {
			fix.Version = info.version
		}

		// Look for remediation details
		fix.Detail = getFixDetail(vuln, productID)
	}

	var ranges []grypeDB.Range
	if constraint != "" {
		ranges = append(ranges, grypeDB.Range{
			Version: grypeDB.Version{
				Type:       getVersionType(info.purl),
				Constraint: constraint,
			},
			Fix: fix,
		})
	}

	return &grypeDB.AffectedPackageHandle{
		OperatingSystem: info.os,
		Package:         grypePackage,
		BlobValue: &grypeDB.PackageBlob{
			CVEs:   []string{vulnID},
			Ranges: ranges,
		},
	}
}

func getVersionType(purl *packageurl.PackageURL) string {
	if purl == nil {
		return "unknown"
	}

	pkgType := pkg.TypeFromPURL(purl.String())
	switch pkgType {
	case pkg.NpmPkg, pkg.GemPkg, pkg.RustPkg, pkg.GoModulePkg:
		return "semver"
	case pkg.RpmPkg:
		return "rpm"
	case pkg.DebPkg:
		return "deb"
	case pkg.ApkPkg:
		return "apk"
	default:
		return strings.ToLower(purl.Type)
	}
}

func getFixDetail(vuln *csaf.Vulnerability, productID csaf.ProductID) *grypeDB.FixDetail {
	if vuln.Remediations == nil {
		return nil
	}

	var refs []grypeDB.Reference

	for _, rem := range vuln.Remediations {
		if rem == nil {
			continue
		}

		// Check if this remediation applies to our product
		appliesToProduct := false
		if rem.ProductIds != nil {
			for _, pid := range *rem.ProductIds {
				if pid != nil && *pid == productID {
					appliesToProduct = true
					break
				}
			}
		}

		if !appliesToProduct && rem.ProductIds != nil {
			continue
		}

		// Add URL as reference if present
		if rem.URL != nil && *rem.URL != "" {
			refs = append(refs, grypeDB.Reference{
				URL:  *rem.URL,
				Tags: []string{grypeDB.AdvisoryReferenceTag},
			})
		}
	}

	if len(refs) == 0 {
		return nil
	}

	return &grypeDB.FixDetail{
		References: refs,
	}
}
