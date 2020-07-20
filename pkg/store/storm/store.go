package storm

import (
	"errors"
	"fmt"
	"github.com/anchore/siren-db/internal"
	"github.com/anchore/siren-db/pkg/db"
	"github.com/anchore/siren-db/pkg/store/storm/model"
	"github.com/asdine/storm/v3"
	"sort"
)

// integrity check
var _ db.Store = &Store{}

type Store struct {
	vulnDb *storm.DB
}

type CleanupFn func() error

// NewStore creates a new instance of the store
func NewStore(dbFilePath string, overwrite bool) (*Store, CleanupFn, error) {
	vulnDb, err := storm.Open(dbFilePath)
	if err != nil {
		return nil, nil, err
	}

	return &Store{
		vulnDb: vulnDb,
	}, vulnDb.Close, nil
}

func (s *Store) GetID() (*db.ID, error) {
	var models []model.ID
	err := s.vulnDb.All(&models)
	if err != nil {
		return nil, fmt.Errorf("failed to get ID: %w", err)
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
	var ids []model.ID

	// replace the existing ID with the given one
	err := s.vulnDb.All(&ids)
	if err != nil {
		return fmt.Errorf("failed find all IDs: %w", err)
	}
	for _, i := range ids {
		err = s.vulnDb.DeleteStruct(i)
		if err != nil {
			return fmt.Errorf("failed delete ID (%+v): %w", i, err)
		}
	}

	m := model.NewIDModel(id)
	if err := s.vulnDb.Save(&m); err != nil {
		return fmt.Errorf("unable to add id: %w", err)
	}

	return nil
}

// Get retrieves one or more vulnerabilities given a namespace and package name
func (s *Store) GetVulnerability(namespace, packageName string) ([]db.Vulnerability, error) {
	var models = make([]model.Vulnerability, 0)

	idx := model.VulnerabilityIndex{
		PackageName: packageName,
		Namespace:   namespace,
	}
	err := s.vulnDb.Find("Index", idx, &models)
	if err != nil {
		return nil, fmt.Errorf("unable to get vulnerablities (index=%+v): %w", idx, err)
	}

	var vulnerabilities = make([]db.Vulnerability, len(models))
	for idx, m := range models {
		vulnerabilities[idx] = m.Inflate()
	}

	return vulnerabilities, nil
}

// AddVulnerability saves a vulnerability in the sqlite3 store
func (s *Store) AddVulnerability(vulnerabilities ...*db.Vulnerability) error {
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		m := model.NewVulnerabilityModel(*vulnerability)

		err := s.vulnDb.Save(&m)
		if err != nil {
			return fmt.Errorf("unable to add vulnerability (%+v): %w", m, err)
		}
	}
	return nil
}

func (s *Store) GetVulnerabilityMetadata(id, recordSource string) (*db.VulnerabilityMetadata, error) {
	var models []model.VulnerabilityMetadata

	idx := model.VulnerabilityMetadataIndex{
		ID: id,
		RecordSource: recordSource,
	}
	err := s.vulnDb.Find("Index", idx, &models)
	if errors.Is(err, storm.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to fetch vulnerability metadata (id=%v, recordSource=%v): %w", id, recordSource, err)
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

			m := model.NewVulnerabilityMetadataModel(*existing)
			err := s.vulnDb.Save(&m)

			if err != nil {
				return fmt.Errorf("unable to merge vulnerability metadata: %w", err)
			}

		} else {
			m := model.NewVulnerabilityMetadataModel(*m)
			// this is a new entry
			err := s.vulnDb.Save(&m)
			if err != nil {
				return fmt.Errorf("unable to save vulnerability metadata: %w", err)
			}
		}
	}
	return nil
}
