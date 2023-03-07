package v3

import (
	"crypto/sha256"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype-db/internal/file"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype/grype/db"
	grypeDB "github.com/anchore/grype/grype/db/v3"
	grypeDBStore "github.com/anchore/grype/grype/db/v3/store"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath string
	store  grypeDB.Store
}

func NewWriter(directory string, dataAge time.Time) (data.Writer, error) {
	dbPath := path.Join(directory, grypeDB.VulnerabilityStoreFileName)
	theStore, err := grypeDBStore.New(dbPath, true)
	if err != nil {
		return nil, fmt.Errorf("unable to create writer: %w", err)
	}

	if err := theStore.SetID(grypeDB.NewID(dataAge)); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	return &writer{
		dbPath: dbPath,
		store:  theStore,
	}, nil
}

func (w writer) Write(entries ...data.Entry) error {
	for _, entry := range entries {
		if entry.DBSchemaVersion != grypeDB.SchemaVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", grypeDB.SchemaVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case grypeDB.Vulnerability:
			if err := w.store.AddVulnerability(row); err != nil {
				return fmt.Errorf("unable to write vulnerability to store: %w", err)
			}
		case grypeDB.VulnerabilityMetadata:
			normalizeSeverity(&row, w.store)
			if err := w.store.AddVulnerabilityMetadata(row); err != nil {
				return fmt.Errorf("unable to write vulnerability metadata to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry does not have a vulnerability or a metadata: %T", row)
		}
	}

	return nil
}

func (w writer) metadata() (*db.Metadata, error) {
	hashStr, err := file.ContentDigest(afero.NewOsFs(), w.dbPath, sha256.New())
	if err != nil {
		return nil, fmt.Errorf("failed to hash database file (%s): %w", w.dbPath, err)
	}

	storeID, err := w.store.GetID()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch store ID: %w", err)
	}

	metadata := db.Metadata{
		Built:    storeID.BuildTimestamp,
		Version:  storeID.SchemaVersion,
		Checksum: "sha256:" + hashStr,
	}
	return &metadata, nil
}

func (w writer) Close() error {
	w.store.Close()
	metadata, err := w.metadata()
	if err != nil {
		return err
	}

	metadataPath := path.Join(filepath.Dir(w.dbPath), db.MetadataFileName)

	return metadata.Write(metadataPath)
}

func normalizeSeverity(metadata *grypeDB.VulnerabilityMetadata, reader grypeDB.VulnerabilityMetadataStoreReader) {
	if metadata.Severity != "" && strings.ToLower(metadata.Severity) != "unknown" {
		return
	}
	if !strings.HasPrefix(strings.ToLower(metadata.ID), "cve") {
		return
	}
	if strings.HasPrefix(metadata.Namespace, grypeDB.NVDNamespace) {
		return
	}
	m, err := reader.GetVulnerabilityMetadata(metadata.ID, grypeDB.NVDNamespace)
	if err != nil {
		log.WithFields("id", metadata.ID, "error", err).Warn("error fetching vulnerability metadata from NVD namespace")
		return
	}
	if m == nil {
		log.WithFields("id", metadata.ID).Debug("unable to find vulnerability metadata from NVD namespace")
		return
	}

	newSeverity := string(data.ParseSeverity(m.Severity))

	log.WithFields("id", metadata.ID, "namespace", metadata.Namespace, "from", metadata.Severity, "to", newSeverity).Trace("overriding irrelevant severity with data from NVD record")

	metadata.Severity = newSeverity
}
