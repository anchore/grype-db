package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/provider"
)

// filterProviders keeps only the providers named in --provider-name. Unlike provider.Providers.Filter,
// it returns an error when a requested name does not match any configured provider, so that a typo
// does not silently produce a database (or pull) that is missing that provider.
func filterProviders(ps provider.Providers, names []string) (provider.Providers, error) {
	if len(names) == 0 {
		return ps, nil
	}

	// de-duplicate first: Filter appends a provider once per matching name, so "-p nvd -p nvd" would
	// otherwise select nvd twice
	requested := strset.New(names...)
	filtered := ps.Filter(requested.List()...)

	found := strset.New()
	for _, p := range filtered {
		found.Add(p.ID().Name)
	}

	missing := strset.Difference(requested, found)

	if missing.Size() > 0 {
		list := missing.List()
		sort.Strings(list)
		return nil, fmt.Errorf("providers requested but not configured: %s (see 'grype-db list-providers', or pass -g to generate provider configs from vunnel)", strings.Join(list, ", "))
	}

	return filtered, nil
}
