package v6

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/epss"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/github"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/kev"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/msrc"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/nvd"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/os"
)

type Config struct {
	NVD nvd.Config
}

type Option func(cfg *Config)

func WithCPEParts(included []string) Option {
	return func(cfg *Config) {
		cfg.NVD.CPEParts = strset.New(included...)
	}
}

func WithInferNVDFixVersions(infer bool) Option {
	return func(cfg *Config) {
		cfg.NVD.InferNVDFixVersions = infer
	}
}

func NewConfig(options ...Option) Config {
	var cfg Config
	for _, option := range options {
		option(&cfg)
	}

	return cfg
}

func Processors(cfg Config) []data.Processor {
	return []data.Processor{
		processors.NewV2GitHubProcessor(github.Transform),
		processors.NewV2MSRCProcessor(msrc.Transform),
		processors.NewV2NVDProcessor(nvd.Transformer(cfg.NVD)),
		processors.NewV2OSProcessor(os.Transform),
		processors.NewV2KEVProcessor(kev.Transform),
		processors.NewV2EPSSProcessor(epss.Transform),
	}
}
