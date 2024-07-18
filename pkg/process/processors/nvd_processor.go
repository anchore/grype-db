package processors

import (
	"github.com/anchore/grype-db/pkg/provider"
	"io"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type nvdProcessor struct {
	transformer any
}

func NewNVDProcessor(transformer data.NVDTransformer) data.Processor {
	return &nvdProcessor{
		transformer: transformer,
	}
}

func NewV2NVDProcessor(transformer data.NVDTransformerV2) data.Processor {
	return &nvdProcessor{
		transformer: transformer,
	}
}

func (p nvdProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.NvdVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	var handle func(entry unmarshal.NVDVulnerability) ([]data.Entry, error)
	switch t := p.transformer.(type) {
	case data.NVDTransformer:
		handle = func(entry unmarshal.NVDVulnerability) ([]data.Entry, error) {
			return t(entry)
		}
	case data.NVDTransformerV2:
		handle = func(entry unmarshal.NVDVulnerability) ([]data.Entry, error) {
			return t(entry, state)
		}
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty NVD entry")
			continue
		}

		transformedEntries, err := handle(entry.Cve)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p nvdProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/nvd/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.0.0.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported NVD schema version")
		return false
	}

	return true
}
