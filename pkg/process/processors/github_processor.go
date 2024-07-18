//nolint:dupl
package processors

import (
	"io"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type githubProcessor struct {
	transformer any
}

func NewGitHubProcessor(transformer data.GitHubTransformer) data.Processor {
	return &githubProcessor{
		transformer: transformer,
	}
}

func NewV2GitHubProcessor(transformer data.GitHubTransformerV2) data.Processor {
	return &githubProcessor{
		transformer: transformer,
	}
}

func (p githubProcessor) Process(reader io.Reader, state provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.GitHubAdvisoryEntries(reader)
	if err != nil {
		return nil, err
	}

	var handle func(entry unmarshal.GitHubAdvisory) ([]data.Entry, error)
	switch t := p.transformer.(type) {
	case data.GitHubTransformer:
		handle = func(entry unmarshal.GitHubAdvisory) ([]data.Entry, error) {
			return t(entry)
		}
	case data.GitHubTransformerV2:
		handle = func(entry unmarshal.GitHubAdvisory) ([]data.Entry, error) {
			return t(entry, state)
		}
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty GHSA entry")
			continue
		}

		transformedEntries, err := handle(entry)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p githubProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/github-security-advisory/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.0.0.json") && !strings.HasSuffix(schemaURL, "schema-1.0.1.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported GHSA schema version")
		return false
	}

	return true
}
