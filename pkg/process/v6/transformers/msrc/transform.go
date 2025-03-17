package msrc

import (
	"strings"

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

func Transform(vulnerability unmarshal.MSRCVulnerability, state provider.State) ([]data.Entry, error) {
	ins := []any{
		getVulnerability(vulnerability, state),
	}

	ins = append(ins, getAffectedPackage(vulnerability))

	return transformers.NewEntries(ins...), nil
}

func getVulnerability(vuln unmarshal.MSRCVulnerability, state provider.State) grypeDB.VulnerabilityHandle {
	return grypeDB.VulnerabilityHandle{
		Name:       vuln.ID,
		ProviderID: state.Provider,
		Provider:   internal.ProviderModel(state),
		Status:     grypeDB.VulnerabilityActive,
		BlobValue: &grypeDB.VulnerabilityBlob{
			ID:          vuln.ID,
			Description: strings.TrimSpace(vuln.Summary),
			References:  getReferences(vuln),
			Severities:  getSeverities(vuln),
		},
	}
}

func getAffectedPackage(vuln unmarshal.MSRCVulnerability) grypeDB.AffectedPackageHandle {
	return grypeDB.AffectedPackageHandle{
		Package: getPackage(vuln),
		BlobValue: &grypeDB.AffectedPackageBlob{
			Ranges: getRanges(vuln),
		},
	}
}

func getPackage(vuln unmarshal.MSRCVulnerability) *grypeDB.Package {
	return &grypeDB.Package{
		Name:      name.Normalize(vuln.Product.ID, pkg.KbPkg),
		Ecosystem: string(pkg.KbPkg),
	}
}

func getRanges(vuln unmarshal.MSRCVulnerability) []grypeDB.AffectedRange {
	// In anchore-enterprise windows analyzer, "base" represents unpatched windows images (images with no KBs)
	// If a vulnerability exists for a Microsoft Product ID and the image has no KBs (which are patches),
	// then the image must be vulnerable to the image.
	vuln.Vulnerable = append(vuln.Vulnerable, "base")

	return []grypeDB.AffectedRange{
		{
			Version: grypeDB.AffectedVersion{
				Type:       "kb",
				Constraint: common.OrConstraints(vuln.Vulnerable...),
			},
			Fix: getFix(vuln),
		},
	}
}

func getFix(vuln unmarshal.MSRCVulnerability) *grypeDB.Fix {
	fixedInVersion := fixedInKB(vuln)

	fixState := grypeDB.FixedStatus
	if fixedInVersion == "" {
		fixState = grypeDB.NotFixedStatus
	}

	return &grypeDB.Fix{
		Version: fixedInVersion,
		State:   fixState,
	}
}

// fixedInKB finds the "latest" patch (KB id) amongst the available microsoft patches and returns it
// if the "latest" patch cannot be found, an empty string is returned
func fixedInKB(vulnerability unmarshal.MSRCVulnerability) string {
	for _, fixedIn := range vulnerability.FixedIn {
		if fixedIn.IsLatest {
			return fixedIn.ID
		}
	}
	return ""
}

func getReferences(vuln unmarshal.MSRCVulnerability) []grypeDB.Reference {
	refs := []grypeDB.Reference{
		{
			URL: vuln.Link,
		},
	}

	return refs
}

func getSeverities(vuln unmarshal.MSRCVulnerability) []grypeDB.Severity {
	var severities []grypeDB.Severity

	cleanSeverity := strings.ToLower(strings.TrimSpace(vuln.Severity))
	if cleanSeverity != "" {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCHML,
			Value:  cleanSeverity,
		})
	}

	if vuln.Cvss.Vector != "" {
		severities = append(severities, grypeDB.Severity{
			Scheme: grypeDB.SeveritySchemeCVSS,
			Value: grypeDB.CVSSSeverity{
				Vector:  vuln.Cvss.Vector,
				Version: "3.0", // TODO: assuming CVSS v3, update if different
			},
		})
	}

	return severities
}
