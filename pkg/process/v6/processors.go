package v6

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/github"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/nvd"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewV2GitHubProcessor(github.Transform),
		//processors.NewMSRCProcessor(msrc.Transform),
		processors.NewV2NVDProcessor(nvd.Transform),
		processors.NewV2OSProcessor(os.Transform),
		//processors.NewMatchExclusionProcessor(matchexclusions.Transform),
	}
}
