package osv

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v5/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v5"
)

func Transform(vulnerability unmarshal.OsvVulnerability) ([]data.Entry, error) {
	vulns, metadata, err := transformImpl(vulnerability)
	if err != nil {
		return nil, err
	}

	return transformers.NewEntries(vulns, metadata), nil
}

func transformImpl(vulnerability unmarshal.OsvVulnerability) ([]grypeDB.Vulnerability, grypeDB.VulnerabilityMetadata, error) {
	/*
		every record in Bitnami currently has "cpes" and "severity" in the database_specific fields:
		$ find data/bitnami/input/vulndb/data -iname '*.json' | xargs jq -c -r '.database_specific | keys' | sort | uniq -c
		3836 ["cpes","severity"]
	*/
	panic("unimplemented")
}
