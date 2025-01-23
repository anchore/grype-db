package transformers

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

type RelatedEntries struct {
	VulnerabilityHandle grypeDB.VulnerabilityHandle
	Related             []any
}

func NewEntries(models ...any) []data.Entry {
	var entry RelatedEntries

	for _, model := range models {
		switch m := model.(type) {
		case grypeDB.VulnerabilityHandle:
			entry.VulnerabilityHandle = m
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

func (re RelatedEntries) String() string {
	var pkgs []string
	for _, r := range re.Related {
		switch v := r.(type) {
		case grypeDB.AffectedPackageHandle:
			pkgs = append(pkgs, v.Package.String())
		case grypeDB.AffectedCPEHandle:
			pkgs = append(pkgs, fmt.Sprintf("%s/%s", v.CPE.Vendor, v.CPE.Product))
		}
	}
	return fmt.Sprintf("vuln=%q provider=%q entries=%d: %s", re.VulnerabilityHandle.Name, re.VulnerabilityHandle.ProviderID, len(re.Related), strings.Join(pkgs, ", "))
}
