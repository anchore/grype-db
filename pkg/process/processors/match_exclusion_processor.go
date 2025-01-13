//nolint:dupl
package processors

import (
	"io"
	"regexp"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type matchExclusionProcessor struct {
	transformer data.MatchExclusionTransformer
}

func NewMatchExclusionProcessor(transformer data.MatchExclusionTransformer) data.Processor {
	return &matchExclusionProcessor{
		transformer: transformer,
	}
}

func (p matchExclusionProcessor) Process(reader io.Reader, _ provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.MatchExclusions(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty match-exclusion entry")
			continue
		}

		transformedEntries, err := p.transformer(entry)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

var v1MatchExclusionSchemaPattern = regexp.MustCompile(`https://.*/vunnel/.*/match-exclusion/schema-1\.\d+\.\d+\.json`)

func (p matchExclusionProcessor) IsSupported(schemaURL string) bool {
	if !v1MatchExclusionSchemaPattern.MatchString(schemaURL) {
		log.WithFields("schema", schemaURL).Trace("unsupported match-exclusion schema version")
		return false
	}

	return true
}
