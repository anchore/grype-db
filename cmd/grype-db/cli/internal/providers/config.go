package providers

import "github.com/anchore/grype-db/internal/log"

type Kind string

const (
	InternalKind Kind = "internal" // reserved, not implemented (golang vulnerability data providers in-repo)
	ExternalKind Kind = "external"
	VunnelKind   Kind = "vunnel" // special case of external
)

type Config struct {
	Identifier `yaml:",inline" mapstructure:",squash"`
	Config     interface{} `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

func (c Config) Redact() {
	if c.Config == nil {
		return
	}
	if r, ok := c.Config.(log.Redactable); ok {
		r.Redact()
	}
}

type Identifier struct {
	Name string `yaml:"name" json:"name" mapstructure:"name"`
	Kind Kind   `yaml:"kind,omitempty" json:"kind" mapstructure:"kind"`
}
