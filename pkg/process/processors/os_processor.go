//nolint:dupl
package processors

import (
	"io"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type osProcessor struct {
	transformer data.OSTransformer
}

func NewOSProcessor(transformer data.OSTransformer) data.Processor {
	return &osProcessor{
		transformer: transformer,
	}
}

func (p osProcessor) Process(reader io.Reader) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.OSVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty OS entry")
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

func (p osProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.0.0.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported OS schema version")
		return false
	}

	return true
}
