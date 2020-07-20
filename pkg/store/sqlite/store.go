package sqlite

import (
	"fmt"
	"sort"

	"github.com/anchore/siren-db/internal"
	"github.com/anchore/siren-db/pkg/db"
	"github.com/anchore/siren-db/pkg/store/sqlite/model"
	"github.com/jinzhu/gorm"

	// provide the sqlite dialect to gorm via import
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// integrity check
var _ db.Store = &Store{}

// Store holds an instance of the database connection
type Store struct {
	vulnDb *gorm.DB
}

type CleanupFn func() error

// NewStore creates a new instance of the store
func NewStore(dbFilePath string, overwrite bool) (*Store, CleanupFn, error) {
	vulnDbObj, err := open(config{
		DbPath:    dbFilePath,
		Overwrite: overwrite,
	})
	if err != nil {
		return nil, nil, err
	}

	// TODO: this will affect schema before we validate we should be using this DB
	vulnDbObj.AutoMigrate(&model.IDModel{})
	vulnDbObj.AutoMigrate(&model.VulnerabilityModel{})
	vulnDbObj.AutoMigrate(&model.VulnerabilityMetadataModel{})

	return &Store{
		vulnDb: vulnDbObj,
	}, vulnDbObj.Close, nil
}

func (s *Store) GetID() (*db.ID, error) {
	var models []model.IDModel
	result := s.vulnDb.Find(&models)
	if result.Error != nil {
		return nil, result.Error
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

func (s *Store) SetID(id db.ID) error {
	var ids []model.IDModel

	// replace the existing ID with the given one
	s.vulnDb.Find(&ids).Delete(&ids)

	m := model.NewIDModel(id)
	result := s.vulnDb.Create(&m)

	if result.RowsAffected != 1 {
		return fmt.Errorf("unable to add id (%d rows affected)", result.RowsAffected)
	}

	return result.Error
}

// Get retrieves one or more vulnerabilities given a namespace and package name
func (s *Store) GetVulnerability(namespace, packageName string) ([]db.Vulnerability, error) {
	var models []model.VulnerabilityModel

	result := s.vulnDb.Where("namespace = ? AND package_name = ?", namespace, packageName).Find(&models)

	var vulnerabilities = make([]db.Vulnerability, len(models))
	for idx, m := range models {
		vulnerabilities[idx] = m.Inflate()
	}

	return vulnerabilities, result.Error
}

// AddVulnerability saves a vulnerability in the sqlite3 store
func (s *Store) AddVulnerability(vulnerabilities ...*db.Vulnerability) error {
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		model := model.NewVulnerabilityModel(*vulnerability)

		result := s.vulnDb.Create(&model)
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected != 1 {
			return fmt.Errorf("unable to add vulnerability (%d rows affected)", result.RowsAffected)
		}
	}
	return nil
}

func (s *Store) GetVulnerabilityMetadata(id, recordSource string) (*db.VulnerabilityMetadata, error) {
	var models []model.VulnerabilityMetadataModel

	result := s.vulnDb.Where(&model.VulnerabilityMetadataModel{ID: id, RecordSource: recordSource}).Find(&models)
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

func (s *Store) AddVulnerabilityMetadata(metadata ...*db.VulnerabilityMetadata) error {
	for _, m := range metadata {
		if m == nil {
			continue
		}

		existing, err := s.GetVulnerabilityMetadata(m.ID, m.RecordSource)
		if err != nil {
			return fmt.Errorf("failed to verify existing entry: %w", err)
		}

		if existing != nil {
			// merge with the existing entry
			if existing.Severity != m.Severity {
				return fmt.Errorf("existing metadata has mismatched severity (%q!=%q)", existing.Severity, m.Severity)
			}

			links := internal.NewStringSetFromSlice(existing.Links)
			for _, l := range m.Links {
				links.Add(l)
			}

			existing.Links = links.ToSlice()
			sort.Strings(existing.Links)

			model := model.NewVulnerabilityMetadataModel(*existing)
			result := s.vulnDb.Save(&model)

			if result.RowsAffected != 1 {
				return fmt.Errorf("unable to merge vulnerability metadata (%d rows affected)", result.RowsAffected)
			}

			if result.Error != nil {
				return result.Error
			}
		} else {
			model := model.NewVulnerabilityMetadataModel(*m)
			// this is a new entry
			result := s.vulnDb.Create(&model)
			if result.Error != nil {
				return result.Error
			}

			if result.RowsAffected != 1 {
				return fmt.Errorf("unable to add vulnerability metadata (%d rows affected)", result.RowsAffected)
			}
		}
	}
	return nil
}
