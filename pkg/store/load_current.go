package store

import (
	"fmt"

	"github.com/anchore/siren-db/pkg/db"
	"github.com/anchore/siren-db/pkg/store/sqlite"
)

// LoadCurrent provides the current default vulnerability store object; currently defaults to sqlite.
func LoadCurrent(path string, overwrite bool) (db.Store, func() error, error) {
	slOptions := sqlite.Options{FilePath: path, Clean: overwrite}
	store, storeCleanupFn, err := sqlite.NewStore(&slOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load current store: %w", err)
	}
	return store, storeCleanupFn, nil
}
