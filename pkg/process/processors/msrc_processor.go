package processors

import (
	"io"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

// msrcProcessor defines the regular expression needed to signal what is supported
type msrcProcessor struct {
	transformer data.MSRCTransformer
}

// NewMSRCProcessor creates a new instance of msrcProcessor particular to MSRC
func NewMSRCProcessor(transformer data.MSRCTransformer) data.Processor {
	return &msrcProcessor{
		transformer: transformer,
	}
}

// Process reads all entries in all metadata matching the supported schema and produces vulnerabilities and their corresponding metadata
func (p msrcProcessor) Process(reader io.Reader, _ provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.MSRCVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.ID == "" {
			log.Warn("dropping empty MSRC entry")
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

func (p msrcProcessor) IsSupported(schemaURL string) bool {
	if !hasSchemaSegment(schemaURL, "msrc") {
		return false
	}

	parsedVersion, err := parseVersion(schemaURL)
	if err != nil {
		log.WithFields("schema", schemaURL, "error", err).Error("failed to parse MSRC schema version")
		return false
	}

	return parsedVersion.Major == 1
}
