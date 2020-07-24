package model

import (
	"time"

	"github.com/anchore/go-version"
	"github.com/anchore/grype-db/pkg/db"
)

const (
	IDTableName = "id"
)

type IDModel struct {
	BuildTimestamp string `gorm:"column:build_timestamp"`
	SchemaVersion  string `gorm:"column:schema_version"`
}

func NewIDModel(id db.ID) IDModel {
	return IDModel{
		BuildTimestamp: id.BuildTimestamp.Format(time.RFC3339Nano),
		SchemaVersion:  id.SchemaVersion.String(),
	}
}

func (IDModel) TableName() string {
	return IDTableName
}

func (m *IDModel) Inflate() db.ID {
	buildTime, err := time.Parse(time.RFC3339Nano, m.BuildTimestamp)
	if err != nil {
		// TODO: just no...
		panic(err)
	}
	return db.ID{
		BuildTimestamp: buildTime,
		SchemaVersion:  *version.Must(version.NewVersion(m.SchemaVersion)),
	}
}
