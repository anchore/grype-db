//nolint:dupl
package processors

import (
	"github.com/anchore/grype-db/pkg/provider"
	"io"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
)

type githubProcessor struct {
	transformer data.GitHubTransformer
}

func NewGitHubProcessor(transformer data.GitHubTransformer) data.Processor {
	return &githubProcessor{
		transformer: transformer,
	}
}

func (p githubProcessor) Process(reader io.Reader, _ provider.State) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.GitHubAdvisoryEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty GHSA entry")
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
