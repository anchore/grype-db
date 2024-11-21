package nvd

import (
	"fmt"
	"strings"

	"github.com/umisama/go-cpe"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/process/internal/common"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
)

const (
	ANY = "*"
	NA  = "-"
)

type pkgCandidate struct {
	Product        string
	Vendor         string
	TargetSoftware string
}

func (p pkgCandidate) String() string {
	return fmt.Sprintf("%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware)
}

func newPkgCandidate(match nvd.CpeMatch) (*pkgCandidate, error) {
	// we are only interested in packages that are vulnerable (not related to secondary match conditioning)
	if !match.Vulnerable {
		return nil, nil
	}

	c, err := cpe.NewItemFromFormattedString(match.Criteria)
	if err != nil {
		return nil, fmt.Errorf("unable to create uniquePkgEntry from '%s': %w", match.Criteria, err)
	}

	// we are only interested in applications, not hardware or operating systems
	if c.Part() != cpe.Application {
		return nil, nil
	}

	return &pkgCandidate{
		Product:        c.Product().String(),
		Vendor:         c.Vendor().String(),
		TargetSoftware: c.TargetSw().String(),
	}, nil
}

func findUniquePkgs(cfgs ...nvd.Configuration) uniquePkgTracker {
	set := newUniquePkgTracker()
	for _, c := range cfgs {
		_findUniquePkgs(set, c.Nodes...)
	}
	return set
}

func _findUniquePkgs(set uniquePkgTracker, ns ...nvd.Node) {
	if len(ns) == 0 {
		return
	}
	for _, node := range ns {
		for _, match := range node.CpeMatch {
			candidate, err := newPkgCandidate(match)
			if err != nil {
				// Do not halt all execution because of being unable to create
				// a PkgCandidate. This can happen when a CPE is invalid which
				// could avoid creating a database
				log.Debugf("unable processing pkg: %v", err)
				continue
			}
			if candidate != nil {
				set.Add(*candidate, match)
			}
		}
	}
}

func buildConstraints(matches []nvd.CpeMatch) string {
	constraints := make([]string, 0)
	for _, match := range matches {
		constraints = append(constraints, buildConstraint(match))
	}
	return common.OrConstraints(constraints...)
}

func buildConstraint(match nvd.CpeMatch) string {
	constraints := make([]string, 0)
	if match.VersionStartIncluding != nil && *match.VersionStartIncluding != "" {
		constraints = append(constraints, fmt.Sprintf(">= %s", *match.VersionStartIncluding))
	} else if match.VersionStartExcluding != nil && *match.VersionStartExcluding != "" {
		constraints = append(constraints, fmt.Sprintf("> %s", *match.VersionStartExcluding))
	}

	if match.VersionEndIncluding != nil && *match.VersionEndIncluding != "" {
		constraints = append(constraints, fmt.Sprintf("<= %s", *match.VersionEndIncluding))
	} else if match.VersionEndExcluding != nil && *match.VersionEndExcluding != "" {
		constraints = append(constraints, fmt.Sprintf("< %s", *match.VersionEndExcluding))
	}

	if len(constraints) == 0 {
		c, err := cpe.NewItemFromFormattedString(match.Criteria)
		if err != nil {
			return ""
		}
		version := c.Version().String()
		if version != ANY && version != NA {
			constraints = append(constraints, fmt.Sprintf("= %s", version))
		}
	}

	return strings.Join(constraints, ", ")
}
