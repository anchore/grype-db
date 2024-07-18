package transformers

import (
	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func NewEntries(models ...any) []data.Entry {
	var entries []data.Entry

	for _, model := range models {
		switch m := model.(type) {
		case grypeDB.VulnerabilityHandle:
			entries = append(entries, packageEntry(m))
		case grypeDB.AffectedPackageHandle:
			entries = append(entries, packageEntry(m))
		case grypeDB.NotAffectedPackageHandle:
			entries = append(entries, packageEntry(m))
		case grypeDB.KnownExploitedVulnerabilityHandle:
			entries = append(entries, packageEntry(m))
		case grypeDB.EpssHandle:
			entries = append(entries, packageEntry(m))
		case grypeDB.AffectedCPEHandle:
			entries = append(entries, packageEntry(m))
		case grypeDB.NotAffectedCPEHandle:
			entries = append(entries, packageEntry(m))
		}
	}

	return entries
}

func packageEntry(m any) data.Entry {
	return data.Entry{
		DBSchemaVersion: grypeDB.SchemaVersion,
		Data:            m,
	}
}
