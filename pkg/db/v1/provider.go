package v1

import (
	"context"
	"time"
)

type DataProvider interface {
	Age() time.Time
	Update(context.Context) error
	Provide() *Entry
}
