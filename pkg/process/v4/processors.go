package v4

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v4/transformers/github"
	"github.com/anchore/grype-db/pkg/process/v4/transformers/matchexclusions"
	"github.com/anchore/grype-db/pkg/process/v4/transformers/msrc"
	"github.com/anchore/grype-db/pkg/process/v4/transformers/nvd"
	"github.com/anchore/grype-db/pkg/process/v4/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewMSRCProcessor(msrc.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
		processors.NewMatchExclusionProcessor(matchexclusions.Transform),
	}
}
