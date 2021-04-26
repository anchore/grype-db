package writer

import (
	"fmt"
	"sort"

	"github.com/anchore/grype-db/internal"
	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype-db/pkg/db/model"
	"github.com/go-test/deep"
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

// CleanupFn is a callback for closing a DB connection.
type CleanupFn func() error

// NewStore creates a new instance of the store.
func NewStore(dbFilePath string, overwrite bool) (*Store, CleanupFn, error) {
	vulnDbObj, err := open(config{
		DbPath:    dbFilePath,
		Overwrite: overwrite,
	})
	if err != nil {
		return nil, nil, err
	}

	// TODO: automigrate could write to the database,
	//  we should be validating the database is the correct database based on the version in the ID table before
	//  automigrating
	vulnDbObj.AutoMigrate(&model.IDModel{})
	vulnDbObj.AutoMigrate(&model.VulnerabilityModel{})
	vulnDbObj.AutoMigrate(&model.VulnerabilityMetadataModel{})

	return &Store{
		vulnDb: vulnDbObj,
	}, vulnDbObj.Close, nil
}

// GetID fetches the metadata about the databases schema version and build time.
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
		id, err := models[0].Inflate()
		if err != nil {
			return nil, err
		}
		return &id, nil
	}

	return nil, nil
}

// SetID stores the databases schema version and build time.
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

// GetVulnerability retrieves one or more vulnerabilities given a namespace and package name.
func (s *Store) GetVulnerability(namespace, packageName string) ([]db.Vulnerability, error) {
	var models []model.VulnerabilityModel

	result := s.vulnDb.Where("namespace = ? AND package_name = ?", namespace, packageName).Find(&models)

	var vulnerabilities = make([]db.Vulnerability, len(models))
	for idx, m := range models {
		vulnerability, err := m.Inflate()
		if err != nil {
			return nil, err
		}
		vulnerabilities[idx] = vulnerability
	}

	return vulnerabilities, result.Error
}

// AddVulnerability saves one or more vulnerabilities into the sqlite3 store.
func (s *Store) AddVulnerability(vulnerabilities ...*db.Vulnerability) error {
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		m := model.NewVulnerabilityModel(*vulnerability)

		result := s.vulnDb.Create(&m)
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected != 1 {
			return fmt.Errorf("unable to add vulnerability (%d rows affected)", result.RowsAffected)
		}
	}
	return nil
}

// GetVulnerabilityMetadata retrieves metadata for the given vulnerability ID relative to a specific record source.
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
		metadata, err := models[0].Inflate()
		if err != nil {
			return nil, err
		}

		return &metadata, nil
	}

	return nil, nil
}

// nolint:gocognit
// AddVulnerabilityMetadata stores one or more vulnerability metadata models into the sqlite DB.
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

			cvssDiffs := deep.Equal(existing.Cvss, m.Cvss)

			switch {
			case existing.Severity != m.Severity:
				return fmt.Errorf("existing metadata has mismatched severity (%q!=%q)", existing.Severity, m.Severity)
			case existing.Description != m.Description:
				return fmt.Errorf("existing metadata has mismatched description (%q!=%q)", existing.Description, m.Description)
			case existing.Cvss != nil && m.Cvss != nil && len(cvssDiffs) > 0:
				// TODO: compare each entry for existence and take unique entries
				return fmt.Errorf("existing metadata has mismatched cvss: %+v", cvssDiffs)
			default:
				existing.Cvss = m.Cvss
			}

			links := internal.NewStringSetFromSlice(existing.Links)
			for _, l := range m.Links {
				links.Add(l)
			}

			existing.Links = links.ToSlice()
			sort.Strings(existing.Links)

			newModel := model.NewVulnerabilityMetadataModel(*existing)
			result := s.vulnDb.Save(&newModel)

			if result.RowsAffected != 1 {
				return fmt.Errorf("unable to merge vulnerability metadata (%d rows affected)", result.RowsAffected)
			}

			if result.Error != nil {
				return result.Error
			}
		} else {
			// this is a new entry
			newModel := model.NewVulnerabilityMetadataModel(*m)
			result := s.vulnDb.Create(&newModel)
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
