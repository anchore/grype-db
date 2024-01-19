package namespace

import (
	"github.com/anchore/grype-db/pkg/db/v4/pkg/resolver"
)

type Namespace interface {
	Provider() string
	Resolver() resolver.Resolver
	String() string
}
