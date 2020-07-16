package memory

import (
	"github.com/anchore/siren-db/pkg/db"
)

// integrity check
var _ db.VulnerabilityStoreWriter = &Store{}
var _ db.VulnerabilityMetadataStoreWriter = &Store{}

// Store holds an instance of the database connection
type Store struct {
	vulnerabilities map[string][]*db.Vulnerability
	metadata        map[string]*db.VulnerabilityMetadata
}

// NewStore creates a new instance of the store
func NewStore() *Store {
	return &Store{
		vulnerabilities: make(map[string][]*db.Vulnerability),
	}
}

func (s *Store) AddVulnerability(vulnerabilities ...*db.Vulnerability) error {
	for _, v := range vulnerabilities {
		if _, ok := s.vulnerabilities[v.Namespace]; !ok {
			s.vulnerabilities[v.Namespace] = make([]*db.Vulnerability, 0)
		}
		s.vulnerabilities[v.Namespace] = append(s.vulnerabilities[v.Namespace], v)
	}
	return nil
}

func (s *Store) All() map[string][]*db.Vulnerability {
	return s.vulnerabilities
}

func (s *Store) AddVulnerabilityMetadata(metadata ...*db.VulnerabilityMetadata) error {
	for _, m := range metadata {
		s.metadata[m.ID] = m
	}

	return nil
}
