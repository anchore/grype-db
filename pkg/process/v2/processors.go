package v2

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v2/transformers/github"
	"github.com/anchore/grype-db/pkg/process/v2/transformers/nvd"
	"github.com/anchore/grype-db/pkg/process/v2/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
	}
}
