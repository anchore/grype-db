package model

import (
	"fmt"
	"time"

	"github.com/anchore/grype-db/pkg/db"
)

const (
	IDTableName = "id"
)

type IDModel struct {
	BuildTimestamp string `gorm:"column:build_timestamp"`
	SchemaVersion  int    `gorm:"column:schema_version"`
}

func NewIDModel(id db.ID) IDModel {
	return IDModel{
		BuildTimestamp: id.BuildTimestamp.Format(time.RFC3339Nano),
		SchemaVersion:  id.SchemaVersion,
	}
}

func (IDModel) TableName() string {
	return IDTableName
}

func (m *IDModel) Inflate() (db.ID, error) {
	buildTime, err := time.Parse(time.RFC3339Nano, m.BuildTimestamp)
	if err != nil {
		return db.ID{}, fmt.Errorf("unable to parse build timestamp (%+v): %w", m.BuildTimestamp, err)
	}

	return db.ID{
		BuildTimestamp: buildTime,
		SchemaVersion:  m.SchemaVersion,
	}, nil
}
