package v2

import (
	"context"
	"time"
)

// DataProvider is an arbiter for a data source. It knows how to access the data, knows how old the data is, can be
// told to update said data, and enumerate all data elements it manages.
type DataProvider interface {
	Age() time.Time
	Update(context.Context) error
	Provide() *Entry
}
