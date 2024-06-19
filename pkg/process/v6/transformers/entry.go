package transformers

import (
	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func NewEntries(vuln grypeDB.Vulnerability, blobs ...grypeDB.Blob) []data.Entry {
	entries := []data.Entry{
		{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		},
	}
	for _, blob := range blobs {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            blob,
		})
	}
	return entries
}
