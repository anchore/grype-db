package model

import (
	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/pkg/db"
	"time"
)

const (
	IdTableName = "id"
)

type IdModel struct {
	BuildTimestamp time.Time `gorm:"column:build_timestamp"`
	SchemaVersion  string    `gorm:"column:schema_version"`
}

func NewIDModel(id db.ID) IdModel {
	return IdModel{
		BuildTimestamp: id.BuildTimestamp,
		SchemaVersion:  id.SchemaVersion.String(),
	}
}

func (IdModel) TableName() string {
	return IdTableName
}

func (m *IdModel) Inflate() db.ID {
	return db.ID{
		BuildTimestamp: m.BuildTimestamp,
		SchemaVersion:  *version.Must(version.NewVersion(m.SchemaVersion)),
	}
}