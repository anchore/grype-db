package db

import (
	"context"
	"time"
)

type VulnerabilityProvider interface {
	Age() time.Time
	Update(context.Context) error
	Provide() (*Vulnerability, error)
}
