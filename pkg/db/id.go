package db

import (
	"time"
)

type ID struct {
	BuildTimestamp time.Time
	SchemaVersion  int
}

type IDReader interface {
	GetID() (*ID, error)
}

type IDWriter interface {
	SetID(ID) error
}

func NewID(age time.Time) ID {
	return ID{
		BuildTimestamp: age.UTC(),
		SchemaVersion:  SchemaVersion,
	}
}
