package pull

import (
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype/grype/db/provider"
)

type ProviderRunConfig struct {
	provider.Identifier `yaml:",inline" mapstructure:",squash"`
	Config              interface{} `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

func (c ProviderRunConfig) Redact() {
	if c.Config == nil {
		return
	}
	if r, ok := c.Config.(log.Redactable); ok {
		r.Redact()
	}
}
