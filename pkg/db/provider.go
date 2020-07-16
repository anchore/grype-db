package db

import (
	"context"
	"time"
)

type DataProvider interface {
	Age() time.Time
	Update(context.Context) error
	Provide() (*Vulnerability, *VulnerabilityMetadata, error)
}
