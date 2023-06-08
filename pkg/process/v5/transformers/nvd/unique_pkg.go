package nvd

import (
	"fmt"
	"strings"

	"github.com/umisama/go-cpe"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/process/common"
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
	PlatformCPE    *string
}

func (p pkgCandidate) String() string {
	if p.PlatformCPE == nil {
		return fmt.Sprintf("%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware)
	}

	return fmt.Sprintf("%s|%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware, *p.PlatformCPE)
}

func newPkgCandidate(match nvd.CpeMatch, platformCPE *string) (*pkgCandidate, error) {
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
		PlatformCPE:    platformCPE,
	}, nil
}

func findUniquePkgs(cfgs ...nvd.Configuration) uniquePkgTracker {
	set := newUniquePkgTracker()
	for _, c := range cfgs {
		_findUniquePkgs(set, c)
	}
	return set
}

func determinePlatformCPEAndNodes(c nvd.Configuration) (*string, []nvd.Node) {
	var platformCPE *string
	nodes := c.Nodes

	// Only retrieve a platform CPE in very specific cases
	if len(nodes) == 2 && c.Operator != nil && *c.Operator == nvd.And {
		if len(nodes[1].CpeMatch) == 1 && !nodes[1].CpeMatch[0].Vulnerable {
			platformCPE = &nodes[1].CpeMatch[0].Criteria
			nodes = []nvd.Node{nodes[0]}
		}
	}

	return platformCPE, nodes
}

func _findUniquePkgs(set uniquePkgTracker, c nvd.Configuration) {
	if len(c.Nodes) == 0 {
		return
	}

	platformCPE, nodes := determinePlatformCPEAndNodes(c)

	for _, node := range nodes {
		for _, match := range node.CpeMatch {
			candidate, err := newPkgCandidate(match, platformCPE)
			if err != nil {
				// Do not halt all execution because of being unable to create
				// a PkgCandidate. This can happen when a CPE is invalid which
				// could avoid creating a database
				log.Debugf("unable processing uniquePkg: %v", err)
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

	return common.OrConstraints(removeDuplicateConstraints(&constraints)...)
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

func removeDuplicateConstraints(constraints *[]string) []string {
	constraintMap := make(map[string]bool)
	uniqueConstraints := make([]string, 0)
	for _, constraint := range *constraints {
		if _, exists := constraintMap[constraint]; !exists {
			constraintMap[constraint] = true
			uniqueConstraints = append(uniqueConstraints, constraint)
		}
	}
	return uniqueConstraints
}
