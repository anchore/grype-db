package v5

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/processors"
	"github.com/anchore/grype-db/pkg/process/v5/transformers/github"
	"github.com/anchore/grype-db/pkg/process/v5/transformers/matchexclusions"
	"github.com/anchore/grype-db/pkg/process/v5/transformers/msrc"
	"github.com/anchore/grype-db/pkg/process/v5/transformers/nvd"
	"github.com/anchore/grype-db/pkg/process/v5/transformers/os"
)

type Config struct {
	NVD nvd.Config
	OS  os.Config
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

func WithNVDDescriptionLength(length int) Option {
	return func(cfg *Config) {
		cfg.NVD.MaxDescriptionLength = length
	}
}

func WithOSDescriptionLength(length int) Option {
	return func(cfg *Config) {
		cfg.OS.MaxDescriptionLength = length
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
		processors.NewGitHubProcessor(github.Transform),
		processors.NewMSRCProcessor(msrc.Transform),
		processors.NewNVDProcessor(nvd.Transformer(cfg.NVD)),
		processors.NewOSProcessor(os.Transformer(cfg.OS)),
		processors.NewMatchExclusionProcessor(matchexclusions.Transform),
	}
}
