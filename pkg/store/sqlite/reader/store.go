package reader

import (
	"fmt"
	"github.com/alicebob/sqlittle"
	"github.com/anchore/siren-db/pkg/db"
	"github.com/anchore/siren-db/pkg/store/sqlite/model"
)

// integrity check
var _ db.StoreReader = &Store{}

// Store holds an instance of the database connection
type Store struct {
	vulnDb *sqlittle.DB
}

type CleanupFn func() error

// NewStore creates a new instance of the store
func NewStore(dbFilePath string) (*Store, CleanupFn, error) {
	vulnDb, err := sqlittle.Open(dbFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open DB: %w", err)
	}

	return &Store{
		vulnDb: vulnDb,
	}, vulnDb.Close, nil
}

func (s *Store) GetID() (*db.ID, error) {
	var models []model.IdModel
	err := s.vulnDb.Select(model.IdTableName, func(r sqlittle.Row) {

	}, "build_timestamp", "schema_version")
	if err != nil {
		return nil, fmt.Errorf("unable to fetch ID: %w", err)
	}

	switch {
	case len(models) > 1:
		return nil, fmt.Errorf("found multiple DB IDs")
	case len(models) == 1:
		id := models[0].Inflate()
		return &id, nil
	}

	return nil, nil
}

// Get retrieves one or more vulnerabilities given a namespace and package name
func (s *Store) GetVulnerability(namespace, packageName string) ([]db.Vulnerability, error) {
	var models []vulnerabilityModel

	result := s.vulnDb.Where("namespace = ? AND package_name = ?", namespace, packageName).Find(&models)

	var vulnerabilities = make([]db.Vulnerability, len(models))
	for idx, m := range models {
		vulnerabilities[idx] = m.Inflate()
	}

	return vulnerabilities, result.Error
}

func (s *Store) GetVulnerabilityMetadata(id, recordSource string) (*db.VulnerabilityMetadata, error) {
	var models []vulnerabilityMetadataModel

	result := s.vulnDb.Where(&vulnerabilityMetadataModel{ID: id, RecordSource: recordSource}).Find(&models)
	if result.Error != nil {
		return nil, result.Error
	}

	switch {
	case len(models) > 1:
		return nil, fmt.Errorf("found multiple metadatas for single ID=%q RecordSource=%q", id, recordSource)
	case len(models) == 1:
		metadata := models[0].Inflate()
		return &metadata, nil
	}

	return nil, nil
}
