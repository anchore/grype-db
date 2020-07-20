package model

import (
	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/pkg/db"
	"time"
)

type ID struct {
	BuildTimestamp time.Time
	SchemaVersion  string
}

func NewIDModel(id db.ID) ID {
	return ID{
		BuildTimestamp: id.BuildTimestamp,
		SchemaVersion:  id.SchemaVersion.String(),
	}
}

func (m *ID) Inflate() db.ID {
	return db.ID{
		BuildTimestamp: m.BuildTimestamp,
		SchemaVersion:  *version.Must(version.NewVersion(m.SchemaVersion)),
	}
}