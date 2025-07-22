package processors

import (
	"io"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type osvProcessor struct {
	transformer data.OSVTransformerV2
}

func NewV2OSVProcessor(transformer data.OSVTransformerV2) data.Processor {
	return &osvProcessor{
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
	if !hasSchemaSegment(schemaURL, "osv") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse NVD schema version")
		return false
	}

	return parsedVersion.Major == 1
}
