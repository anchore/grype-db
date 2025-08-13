package openvex

import (
	"fmt"
	"sort"

	"github.com/anchore/packageurl-go"
	govex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
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
	pkgs, err := getAffectedPackages(&vulnerability)
	if err != nil {
		return nil, err
	}
	in := []any{vulnHandle}
	for _, a := range pkgs {
		in = append(in, a)
	}
	return transformers.NewEntries(in...), nil
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

func getAffectedPackages(vuln *unmarshal.OpenVEXVulnerability) ([]grypeDB.AffectedPackageHandle, error) {
	if len(vuln.Products) == 0 {
		return nil, nil
	}

	var aphs []grypeDB.AffectedPackageHandle
	for _, product := range vuln.Products {
		purl, err := packageurl.FromString(product.ID)
		if err != nil {
			return nil, err
		}

		id := getName(vuln)
		cves := []string{id}
		cves = append(cves, getAliases(vuln)...)

		aph := grypeDB.AffectedPackageHandle{
			Package: &grypeDB.Package{
				Ecosystem: string(syft.TypeFromPURL(product.ID)),
				Name:      purl.Name,
			},
			BlobValue: &grypeDB.AffectedPackageBlob{
				CVEs: cves,
				// semantic versioning
				Ranges: getGrypeRanges(&purl, vuln.Status),
			},
		}
		aphs = append(aphs, aph)
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(aphs))

	return aphs, nil
}

// OpenVEX will define affected via a purl in the component and status enum:
//
//	Component{
//	  ID: "pkg:pypi/urllib3@1.26.16+cgr.1"
//	}
//
// Status: affected | not_affected | fixed | under_investigation
func getGrypeRanges(purl *packageurl.PackageURL, status govex.Status) []grypeDB.AffectedRange {
	ret := make([]grypeDB.AffectedRange, 0)

	switch status {
	case govex.StatusAffected:
		ret = append(ret, grypeDB.AffectedRange{
			Version: grypeDB.AffectedVersion{
				Type:       "semver",
				Constraint: fmt.Sprintf("== %s", purl.Version),
			},
		})
	case govex.StatusNotAffected:
		ret = append(ret, grypeDB.AffectedRange{
			Fix: &grypeDB.Fix{
				Version: purl.Version,
				State:   grypeDB.NotAffectedFixStatus,
			},
		})
	case govex.StatusFixed:
		ret = append(ret,
			grypeDB.AffectedRange{
				Fix: &grypeDB.Fix{
					Version: purl.Version,
					State:   grypeDB.FixedStatus,
				},
			},
		)
	}
	return ret
}
