package v3

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v3/transformers/github"
	"github.com/anchore/grype-db/pkg/process/v3/transformers/msrc"
	"github.com/anchore/grype-db/pkg/process/v3/transformers/nvd"
	"github.com/anchore/grype-db/pkg/process/v3/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewMSRCProcessor(msrc.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
	}
}
