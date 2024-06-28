package v6

import (
	"crypto/sha256"
	"fmt"
	"github.com/anchore/grype-db/internal/file"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype/grype/db"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/spf13/afero"
	"path"
	"path/filepath"
	"time"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath string
	store  grypeDB.Store
	states provider.States
}

type ProviderMetadata struct {
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Name              string    `json:"name"`
	LastSuccessfulRun time.Time `json:"lastSuccessfulRun"`
}

func NewWriter(directory string, dataAge time.Time, states provider.States) (data.Writer, error) {
	cfg := grypeDB.StoreConfig{
		BatchSize: 100,
		DBDirPath: directory,
		Overwrite: true,
	}
	theStore, err := grypeDB.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	// TODO:...
	//if err := theStore.SetID(grypeDB.NewID(dataAge)); err != nil {
	//	return nil, fmt.Errorf("unable to set DB ID: %w", err)
	//}

	return &writer{
		dbPath: cfg.DBFilePath(),
		store:  theStore,
		states: states,
	}, nil
}

func (w writer) Write(entries ...data.Entry) error {
	log.WithFields("records", len(entries)).Trace("writing records to DB")
	for _, entry := range entries {
		if entry.DBSchemaVersion != grypeDB.SchemaVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", grypeDB.SchemaVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case grypeDB.Vulnerability:
			if err := w.store.AddVulnerabilities(&row); err != nil {
				return fmt.Errorf("unable to write vulnerability to store: %w", err)
			}
		case grypeDB.Blob:
			if err := w.store.AddBlobs(&row); err != nil {
				return fmt.Errorf("unable to write blob to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

func (w writer) writeMetadata() (*db.Metadata, error) {
	hashStr, err := file.ContentDigest(afero.NewOsFs(), w.dbPath, sha256.New())
	if err != nil {
		return nil, fmt.Errorf("failed to hash database file (%s): %w", w.dbPath, err)
	}

	// TODO:...
	//storeID, err := w.store.GetID()
	//if err != nil {
	//	return nil, fmt.Errorf("failed to fetch store ID: %w", err)
	//}

	metadata := db.Metadata{
		// TODO:...
		//Built:    storeID.BuildTimestamp,
		//Version:  storeID.SchemaVersion,
		Checksum: "sha256:" + hashStr,
	}
	return &metadata, nil
}

func (w writer) Close() error {
	w.store.Close()
	metadata, err := w.writeMetadata()
	if err != nil {
		return fmt.Errorf("unable to write DB metadata file: %w", err)
	}

	metadataPath := path.Join(filepath.Dir(w.dbPath), db.MetadataFileName)
	if err = metadata.Write(metadataPath); err != nil {
		return err
	}

	log.WithFields("path", w.dbPath).Info("database created")
	log.WithFields("path", metadataPath).Debug("database metadata created")

	return nil
}
