package v6

import (
	"fmt"
	"time"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath        string
	store         grypeDB.ReadWriter
	providerCache map[string]grypeDB.Provider
	states        provider.States
}

type ProviderMetadata struct {
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Name              string    `json:"name"`
	LastSuccessfulRun time.Time `json:"lastSuccessfulRun"`
}

func NewWriter(directory string, states provider.States) (data.Writer, error) {
	cfg := grypeDB.Config{
		DBDirPath: directory,
	}
	s, err := grypeDB.NewWriter(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	if err := s.SetDBMetadata(); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	return &writer{
		dbPath:        cfg.DBFilePath(),
		providerCache: make(map[string]grypeDB.Provider),
		store:         s,
		states:        states,
	}, nil
}

func (w writer) Write(entries ...data.Entry) error {
	for _, entry := range entries {
		if entry.DBSchemaVersion != grypeDB.ModelVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", grypeDB.ModelVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case transformers.RelatedEntries:
			if err := w.writeEntry(row); err != nil {
				return fmt.Errorf("unable to write entry to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

func (w writer) writeEntry(entry transformers.RelatedEntries) error {
	if entry.VulnerabilityHandle.Provider != nil {
		if _, ok := w.providerCache[entry.VulnerabilityHandle.Provider.ID]; !ok {
			p := entry.VulnerabilityHandle.Provider
			if err := w.store.AddProvider(p); err != nil {
				return fmt.Errorf("unable to write provider to store: %w", err)
			}
			w.providerCache[p.ID] = *p
		} else {
			// exists! don't attempt to write it again
			entry.VulnerabilityHandle.Provider = nil
		}
	}

	if err := w.store.AddVulnerabilities(&entry.VulnerabilityHandle); err != nil {
		return fmt.Errorf("unable to write vulnerability to store: %w", err)
	}

	for i := range entry.Related {
		related := entry.Related[i]
		switch row := related.(type) {
		case grypeDB.AffectedPackageHandle:
			row.VulnerabilityID = entry.VulnerabilityHandle.ID
			if err := w.store.AddAffectedPackages(&row); err != nil {
				return fmt.Errorf("unable to write affected-package to store: %w", err)
			}
		case grypeDB.AffectedCPEHandle:
			row.VulnerabilityID = entry.VulnerabilityHandle.ID
			if err := w.store.AddAffectedCPEs(&row); err != nil {
				return fmt.Errorf("unable to write affected-cpe to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

func (w writer) Close() error {
	if err := w.store.Close(); err != nil {
		return fmt.Errorf("unable to close store: %w", err)
	}

	log.WithFields("path", w.dbPath).Info("database created")

	return nil
}
