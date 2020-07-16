package db

import (
	"time"

	"github.com/anchore/go-version"
)

type ID struct {
	BuildTimestamp time.Time
	SchemaVersion  version.Version
}

type IDReader interface {
	GetID() (ID, error)
}

type IDWriter interface {
	SetID(ID) error
}

func NewID(age time.Time) ID {
	return ID{
		BuildTimestamp: age.UTC(),
		SchemaVersion:  *version.Must(version.NewVersion(SchemaVersion)),
	}
}
