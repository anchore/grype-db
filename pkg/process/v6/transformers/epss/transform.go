package epss

import (
	"fmt"
	"time"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func Transform(entry unmarshal.EPSS, state provider.State) ([]data.Entry, error) {
	date := internal.ParseTime(entry.Date)
	if date == nil {
		return nil, fmt.Errorf("failed to parse date: %q", entry.Date)
	}
	return transformers.NewEntries(*internal.ProviderModel(state), getEPSS(entry, *date)), nil
}

func getEPSS(entry unmarshal.EPSS, date time.Time) grypeDB.EpssHandle {
	return grypeDB.EpssHandle{
		Cve:        entry.CVE,
		Epss:       entry.EPSS,
		Percentile: entry.Percentile,
		Date:       date,
	}
}
