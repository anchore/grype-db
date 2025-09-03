package openvex

import (
	"fmt"
	"sort"

	govex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/packageurl-go"
	syft "github.com/anchore/syft/syft/pkg"
)

// Transform an openvex vulnerability into data entries.
//
//	satisifies pkg/data/OpenVexTransformerV2
func Transform(vulnerability unmarshal.OpenVEXVulnerability, state provider.State) ([]data.Entry, error) {
	name := getName(&vulnerability)
	vulnHandle := grypeDB.VulnerabilityHandle{
		Name:          name,
		Status:        grypeDB.VulnerabilityActive,
		PublishedDate: vulnerability.Timestamp,
		ModifiedDate:  vulnerability.LastUpdated,
		ProviderID:    state.Provider,
		Provider:      internal.ProviderModel(state),
		BlobValue: &grypeDB.VulnerabilityBlob{
			ID:          name,
			Assigners:   nil,
			Description: vulnerability.Vulnerability.Description,
			References:  getReferences(&vulnerability),
			Aliases:     getAliases(&vulnerability),
		},
	}
	pkgs, err := getPackageHandles(&vulnerability)
	if err != nil {
		return nil, err
	}
	in := []any{vulnHandle}
	in = append(in, pkgs...)
	return transformers.NewEntries(in...), nil
}

// getPackageHandles for all products in this advisory
func getPackageHandles(vuln *unmarshal.OpenVEXVulnerability) ([]any, error) {
	if len(vuln.Products) == 0 {
		return nil, nil
	}

	var aphs []any
	for _, product := range vuln.Products {
		aph, err := getPackageHandle(&product, vuln)
		if err != nil {
			return nil, err
		}
		aphs = append(aphs, aph)
	}

	sort.Sort(internal.ByAny(aphs))

	return aphs, nil
}

// getPackageHandle for a single product
//
// OpenVEX defines product via:
//
//	Component {
//	  Identifiers: {
//	    PURLIdentifierType: pkg:type/name@version
//	  }
//	}
func getPackageHandle(product *govex.Product, vuln *unmarshal.OpenVEXVulnerability) (ret any, err error) {
	if product == nil || vuln == nil {
		return ret, fmt.Errorf("getAffectedPackage params cannot be nil")
	}
	purl, err := getPURL(product)
	if err != nil {
		return ret, fmt.Errorf("failed to parse purl %s: %w", purl, err)
	}

	pkg := &grypeDB.Package{
		Ecosystem: string(syft.TypeFromPURL(purl.String())),
		Name:      purl.Name,
	}

	aliases := []string{getName(vuln)}
	aliases = append(aliases, getAliases(vuln)...)

	switch vuln.Status {
	case govex.StatusAffected:
		ret = grypeDB.AffectedPackageHandle{
			Package:   pkg,
			BlobValue: getAffectedBlob(aliases, purl.Version, purl.Type),
		}
	case govex.StatusNotAffected:
		ret = grypeDB.UnaffectedPackageHandle{
			Package:   pkg,
			BlobValue: getUnaffectedBlob(aliases, purl.Version, purl.Type, grypeDB.NotAffectedFixStatus),
		}
	case govex.StatusFixed:
		ret = grypeDB.UnaffectedPackageHandle{
			Package:   pkg,
			BlobValue: getUnaffectedBlob(aliases, purl.Version, purl.Type, grypeDB.FixedStatus),
		}
	default:
		err = fmt.Errorf("invalid vuln states %s", vuln.Status)
	}
	return ret, err
}

// getPURL from either ID field or identifiers
func getPURL(product *govex.Product) (purl *packageurl.PackageURL, err error) {
	if p, ok := product.Identifiers[govex.PURL]; ok {
		purl, err := packageurl.FromString(p)
		if err != nil {
			return nil, fmt.Errorf("failed to parse purl %s: %w", p, err)
		}
		return &purl, nil
	}
	if product.ID != "" {
		purl, err := packageurl.FromString(product.ID)
		if err != nil {
			return nil, err
		}
		return &purl, nil
	}
	return nil, fmt.Errorf("invalid product: %v", product)
}

func getAliases(vuln *unmarshal.OpenVEXVulnerability) []string {
	ret := make([]string, 0, len(vuln.Vulnerability.Aliases))
	for _, alias := range vuln.Vulnerability.Aliases {
		ret = append(ret, string(alias))
	}
	return ret
}

func getName(vuln *unmarshal.OpenVEXVulnerability) string {
	return string(vuln.Vulnerability.Name)
}

func getReferences(vuln *unmarshal.OpenVEXVulnerability) []grypeDB.Reference {
	refs := []grypeDB.Reference{
		{
			URL: getName(vuln),
		},
	}
	return refs
}

// getAffectedBlob creates a package blob for affected packages
func getAffectedBlob(aliases []string, ver string, ty string) *grypeDB.PackageBlob {
	return &grypeDB.PackageBlob{
		CVEs: aliases,
		// semantic versioning
		Ranges: []grypeDB.Range{
			{
				Version: grypeDB.Version{
					Type:       version.ParseFormat(ty).String(),
					Constraint: fmt.Sprintf("= %s", ver),
				},
			},
		},
	}
}

// getUnaffectedBlob creates a package blob for unaffected packages (has a fix)
func getUnaffectedBlob(aliases []string, ver string, ty string, fixState grypeDB.FixStatus) *grypeDB.PackageBlob {
	return &grypeDB.PackageBlob{
		CVEs: aliases,
		Ranges: []grypeDB.Range{
			{
				Version: grypeDB.Version{
					Type:       version.ParseFormat(ty).String(),
					Constraint: fmt.Sprintf("= %s", ver),
				},
				Fix: &grypeDB.Fix{
					Version: ver,
					State:   fixState,
				},
			},
		},
	}
}
