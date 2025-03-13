package processors

import (
	"io"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type osvProcessor struct {
	transformer data.OSVTransformerV2
}

func NewV2OSVProcessor(transformer data.OSTransformerV2) data.Processor {
	return &osProcessor{
		transformer: transformer,
	}
}

func (p osvProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.OSVVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		transformedEntries, err := p.transformer(entry, state)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p osvProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/osv/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.6.1.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported OSV schema version")
		return false
	}

	return true
}
