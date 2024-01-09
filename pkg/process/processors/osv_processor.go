package processors

import (
	"io"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type osvProcessor struct {
	transformer data.OSVTransformer
}

func NewOSVProcessor(transformer data.OSVTransformer) data.Processor {
	return &osvProcessor{
		transformer: transformer,
	}
}

func (p osvProcessor) Process(reader io.Reader) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.OSVVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		transformedEntries, err := p.transformer(entry)
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
