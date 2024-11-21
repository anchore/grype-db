package transformers

import (
	"fmt"

	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

type RelatedEntries struct {
	VulnerabilityHandle grypeDB.VulnerabilityHandle
	Provider            grypeDB.Provider
	Related             []any
}

func NewEntries(models ...any) []data.Entry {
	var entry RelatedEntries

	for _, model := range models {
		switch m := model.(type) {
		case grypeDB.VulnerabilityHandle:
			entry.VulnerabilityHandle = m
		case grypeDB.Provider:
			entry.Provider = m
		case grypeDB.AffectedPackageHandle:
			entry.Related = append(entry.Related, m)
		case grypeDB.AffectedCPEHandle:
			entry.Related = append(entry.Related, m)
		default:
			panic(fmt.Sprintf("unsupported model type: %T", m))
		}
	}

	return []data.Entry{
		{
			DBSchemaVersion: grypeDB.ModelVersion,
			Data:            entry,
		},
	}
}
