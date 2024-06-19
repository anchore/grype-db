package v6

import (
	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		//processors.NewGitHubProcessor(github.Transform),
		//processors.NewMSRCProcessor(msrc.Transform),
		//processors.NewNVDProcessor(nvd.Transform),
		processors.NewV2OSProcessor(os.Transform),
		//processors.NewMatchExclusionProcessor(matchexclusions.Transform),
	}
}
