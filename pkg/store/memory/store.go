package memory

import (
	"github.com/anchore/siren-db/pkg/db"
)

// integrity check
var _ db.VulnerabilityStoreWriter = &Store{}

// Store holds an instance of the database connection
type Store struct {
	db map[string][]*db.Vulnerability
}

// NewStore creates a new instance of the store
func NewStore() *Store {
	return &Store{
		db: make(map[string][]*db.Vulnerability),
	}
}

func (b *Store) AddVulnerability(vulns ...*db.Vulnerability) error {
	for _, v := range vulns {
		if _, ok := b.db[v.Namespace]; !ok {
			b.db[v.Namespace] = make([]*db.Vulnerability, 0)
		}
		b.db[v.Namespace] = append(b.db[v.Namespace], v)
	}
	return nil
}

func (b *Store) All() map[string][]*db.Vulnerability {
	return b.db
}
