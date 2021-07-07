package v3

import (
	"context"
	"time"
)

type DataProvider interface {
	Age() time.Time
	Update(context.Context) error
	Provide() *Entry
}
