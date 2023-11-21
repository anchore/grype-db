package nvd

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/process/common"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
	"github.com/umisama/go-cpe"
)

const (
	ANY = "*"
	NA  = "-"
)

type pkgCandidate struct {
	Product        string
	Vendor         string
	TargetSoftware string
	PlatformCPE    string
}

func (p pkgCandidate) String() string {
	if p.PlatformCPE == "" {
		return fmt.Sprintf("%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware)
	}

	return fmt.Sprintf("%s|%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware, p.PlatformCPE)
}

func newPkgCandidate(match nvd.CpeMatch, platformCPE string) (*pkgCandidate, error) {
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

func platformPackageCandidates(set uniquePkgTracker, c nvd.Configuration) bool {
	nodes := c.Nodes
	result := false
	/*
		Turn a configuration like this:
		(AND (redis <= 6.2 (OR debian:8 debian:9 ubuntu:19 ubuntu:20))
		Into a configuration like this:
		(OR (AND redis <= 6.1 debian:8) (AND redis <= 6.1 debian:9) (AND redis <= 6.1 ubuntu:19) (AND redis <= 6.1 ubuntu:20))
	*/
	if len(nodes) == 2 && c.Operator != nil && *c.Operator == nvd.And && len(nodes[0].CpeMatch) == 1 {
		matches := nodes[1].CpeMatch
		applicationNode := nodes[0].CpeMatch[0]
		for _, maybePlatform := range matches {
			// TODO: I'm overwriting a pointer or something?
			// Something stupid is happening. Every time this loop steps, I'm overwriting
			// the zeroth member of the set.
			platform := maybePlatform.Criteria
			candidate, err := newPkgCandidate(applicationNode, platform)
			if err != nil || candidate == nil {
				continue
			}
			set.Add(*candidate, nodes[0].CpeMatch[0])
			result = true
		}

	}
	return result
}

func determinePlatformCPEAndNodes(c nvd.Configuration) (string, []nvd.Node) {
	var platformCPE string
	nodes := c.Nodes

	// Only retrieve a platform CPE in very specific cases
	// WILL - I need to figure out what these
	if len(nodes) == 2 && c.Operator != nil && *c.Operator == nvd.And {
		if len(nodes[1].CpeMatch) == 1 && !nodes[1].CpeMatch[0].Vulnerable { // WILL: this is false for the record in question
			// Here's what I think is happening:
			// Right now, if there is _exactly one_ platform
			// we set that platform on the vuln record we emit
			// but if there is more than one, we just punt
			// and say, "who knows; lots of platforms."
			// instead, we should figure out how to or together the platforms
			// and emit the fewest number of rows that covers all cases.
			//
			/*

				TODAY:
				sqlite> select id, package_name, namespace, package_qualifiers, version_constraint from vulnerability where id like 'CVE-2022-0543';
				id             package_name  namespace                             package_qualifiers  version_constraint
				-------------  ------------  ------------------------------------  ------------------  ---------------------
				CVE-2022-0543  redis         nvd:cpe

				This should really look more like:

				sqlite> select id, package_name, namespace, package_qualifiers, version_constraint from vulnerability where id like 'CVE-2022-0543';
				id             package_name  namespace                             package_qualifiers  version_constraint
				-------------  ------------  ------------------------------------  ------------------  ---------------------
				CVE-2022-0543  redis         nvd:cpe								[{"kind":"platform-cpe","cpe":"cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*"}]
				CVE-2022-0543  redis         nvd:cpe								[{"kind":"platform-cpe","cpe":"cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*"}]
				CVE-2022-0543  redis         nvd:cpe								[{"kind":"platform-cpe","cpe":"cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*"}]
				CVE-2022-0543  redis         nvd:cpe								[{"kind":"platform-cpe","cpe":"cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"}]
				CVE-2022-0543  redis         nvd:cpe								[{"kind":"platform-cpe","cpe":"cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*"}]
			*/
			platformCPE = nodes[1].CpeMatch[0].Criteria
			nodes = []nvd.Node{nodes[0]}
		}
	}

	// This needs to return multiple nodes?

	return platformCPE, nodes
}

func _findUniquePkgs(set uniquePkgTracker, c nvd.Configuration) {
	if len(c.Nodes) == 0 {
		return
	}

	if platformPackageCandidates(set, c) {
		return
	}

	platformCPE, nodes := determinePlatformCPEAndNodes(c)
	//
	//// TODO: this needs to loop also the other way;
	//// we need to be able to represent a single package
	//// that has multiple platforms,
	//// probably by
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
		update := c.Update().String()
		if version != ANY && version != NA {
			if update != ANY && update != NA {
				version = fmt.Sprintf("%s-%s", version, update)
			}

			constraints = append(constraints, fmt.Sprintf("= %s", version))
		}
	}

	return strings.Join(constraints, ", ")
}
