package transformers

import (
	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype-db/pkg/db/v4"
)

func NewEntries(vs []grypeDB.Vulnerability, metadata grypeDB.VulnerabilityMetadata) []data.Entry {
	entries := []data.Entry{
		{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            metadata,
		},
	}
	for _, vuln := range vs {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		})
	}
	return entries
}
