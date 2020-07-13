package db

import (
	"time"

	"github.com/anchore/go-version"
)

// SchemaVersion should be bumped in semantic-version-fashion when there is a change to the underlying database types and data shapes
var SchemaVersion = "0.1.0"

type ID struct {
	BuildTimestamp time.Time
	SchemaVersion  *version.Version
}

func NewID(age time.Time) ID {
	return ID{
		BuildTimestamp: age.UTC(),
		SchemaVersion:  version.Must(version.NewVersion(SchemaVersion)),
	}
}
