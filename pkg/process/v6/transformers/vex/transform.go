package vex

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
)

func Transform(vulnerability unmarshal.VEXVulnerability, state provider.State) ([]data.Entry, error) {
	in := []any{
		grypeDB.VulnerabilityHandle{
			Name:          string(vulnerability.Vulnerability.ID),
			ProviderID:    state.Provider,
			Provider:      internal.ProviderModel(state),
			Status:        grypeDB.VulnerabilityActive,
			ModifiedDate:  vulnerability.LastUpdated,
			PublishedDate: vulnerability.Timestamp,
			BlobValue: &grypeDB.VulnerabilityBlob{
				ID:          string(vulnerability.Vulnerability.ID),
				Assigners:   nil,
				Description: vulnerability.Vulnerability.Description,
				References:  getReferences(vulnerability),
				Aliases:     getAliases(vulnerability),
			},
		},
	}
	pkgs, err := getAffectedPackages(vulnerability)
	if err != nil {
		return nil, err
	}
	for _, a := range pkgs {
		in = append(in, a)
	}
	return transformers.NewEntries(in...), nil
}

func getAliases(vuln unmarshal.VEXVulnerability) []string {
	ret := make([]string, 0, len(vuln.Vulnerability.Aliases))
	for _, alias := range vuln.Vulnerability.Aliases {
		ret = append(ret, string(alias))
	}
	return ret
}

func getReferences(vuln unmarshal.VEXVulnerability) []grypeDB.Reference {
	refs := []grypeDB.Reference{
		{
			URL: vuln.Vulnerability.ID,
		},
	}
	return refs
}

func getAffectedPackages(vuln unmarshal.VEXVulnerability) ([]grypeDB.AffectedPackageHandle, error) {
	if len(vuln.Products) == 0 {
		return nil, nil
	}

	var aphs []grypeDB.AffectedPackageHandle
	for _, product := range vuln.Products {
		purl, err := packageurl.FromString(product.ID)
		if err != nil {
			return nil, err
		}
		ecosystem := purl.Type
		if purl.Namespace != "" {
			ecosystem = purl.Namespace
		}

		cves := []string{string(vuln.Vulnerability.ID)}
		cves = append(cves, getAliases(vuln)...)

		aph := grypeDB.AffectedPackageHandle{
			Package: &grypeDB.Package{
				Ecosystem: ecosystem,
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

// VEX will define affected via a purl in the component and status enum:
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
		// indicate this specific version is affected
		ret = append(ret, grypeDB.AffectedRange{
			Version: grypeDB.AffectedVersion{
				Type:       "semver",
				Constraint: fmt.Sprintf("== %s", purl.Version),
			},
		})
	case govex.StatusNotAffected:
		// indicate this specific version is not affected
		ret = append(ret, grypeDB.AffectedRange{
			Fix: &grypeDB.Fix{
				Version: purl.Version,
				State:   grypeDB.NotAffectedFixStatus,
			},
		})
	case govex.StatusFixed:
		// indicate that this version is fixed and lower versions are vulnerable
		ret = append(ret,
			grypeDB.AffectedRange{
				Version: grypeDB.AffectedVersion{
					Type:       "semver",
					Constraint: fmt.Sprintf("< %s", purl.Version),
				},
			},
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
