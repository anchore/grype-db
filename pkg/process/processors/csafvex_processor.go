package processors

import (
	"io"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type csafVEXProcessor struct {
	transformer data.CSAFVEXTransformerV2
}

func NewV2CSAFVEXProcessor(transformer data.CSAFVEXTransformerV2) data.Processor {
	return &csafVEXProcessor{
		transformer: transformer,
	}
}

func (p csafVEXProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.CSAFVEXVulnerabilityEntries(reader)
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

func (p csafVEXProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "csaf-vex") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse CSAF VEX schema version")
		return false
	}

	// CSAF VEX 2.x (supports both 2.0 and 2.1)
	return parsedVersion.Major == 2
}
