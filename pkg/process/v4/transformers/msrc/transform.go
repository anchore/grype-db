package msrc

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/internal/common"
	"github.com/anchore/grype-db/pkg/process/v4/transformers"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v4"
	"github.com/anchore/grype/grype/db/v4/namespace"
	"github.com/anchore/grype/grype/distro"
)

const (
	// TODO: tech debt from a previous design
	feed        = "microsoft"
	groupPrefix = "msrc"
)

func buildGrypeNamespace(feed, group string) (namespace.Namespace, error) {
	if feed != "microsoft" || !strings.HasPrefix(group, "msrc:") {
		return nil, fmt.Errorf("invalid source for feed=%s, group=%s", feed, group)
	}
	components := strings.Split(group, ":")

	if len(components) != 2 {
		return nil, fmt.Errorf("invalid source for feed=%s, group=%s", feed, group)
	}
	ns, err := namespace.FromString(fmt.Sprintf("msrc:distro:%s:%s", distro.Windows, components[1]))

	if err != nil {
		return nil, err
	}

	return ns, nil
}

// Transform gets called by the parser, which consumes entries from the JSON files previously pulled. Each VulnDBVulnerability represents
// a single unmarshalled entry from the feed service
func Transform(vulnerability unmarshal.MSRCVulnerability) ([]data.Entry, error) {
	group := fmt.Sprintf("%s:%s", groupPrefix, vulnerability.Product.ID)
	recordSource := fmt.Sprintf("%s:%s", feed, group)
	grypeNamespace, err := buildGrypeNamespace(feed, group)
	if err != nil {
		return nil, err
	}

	entryNamespace := grypeNamespace.String()

	// In anchore-enterprise windows analyzer, "base" represents unpatched windows images (images with no KBs).
	// If a vulnerability exists for a Microsoft Product ID and the image has no KBs (which are patches),
	// then the image must be vulnerable to the image.
	//nolint:gocritic
	versionConstraint := append(vulnerability.Vulnerable, "base")

	allVulns := []grypeDB.Vulnerability{
		{
			ID:                vulnerability.ID,
			VersionConstraint: common.OrConstraints(versionConstraint...),
			VersionFormat:     "kb",
			PackageName:       grypeNamespace.Resolver().Normalize(vulnerability.Product.ID),
			Namespace:         entryNamespace,
			Fix:               getFix(vulnerability),
		},
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.ID,
		DataSource:   vulnerability.Link,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     vulnerability.Severity,
		URLs:         []string{vulnerability.Link},
		// There is no description for vulnerabilities from the feed service
		// summary gives something like "windows information disclosure vulnerability"
		//Description:  vulnerability.Summary,
		Cvss: []grypeDB.Cvss{
			{
				Metrics: grypeDB.CvssMetrics{BaseScore: vulnerability.Cvss.BaseScore},
				Vector:  vulnerability.Cvss.Vector,
			},
		},
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getFix(entry unmarshal.MSRCVulnerability) grypeDB.Fix {
	fixedInVersion := fixedInKB(entry)
	fixState := grypeDB.FixedState

	if fixedInVersion == "" {
		fixState = grypeDB.NotFixedState
	}

	return grypeDB.Fix{
		Versions: []string{fixedInVersion},
		State:    fixState,
	}
}

// fixedInKB finds the "latest" patch (KB id) amongst the available microsoft patches and returns it
// if the "latest" patch cannot be found, an error is returned
func fixedInKB(vulnerability unmarshal.MSRCVulnerability) string {
	for _, fixedIn := range vulnerability.FixedIn {
		if fixedIn.IsLatest {
			return fixedIn.ID
		}
	}
	return ""
}
