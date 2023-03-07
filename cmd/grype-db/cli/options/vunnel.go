package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/internal/log"
)

var _ Interface = &Vunnel{}

type Vunnel struct {
	// bound options
	// (none)

	// unbound options
	Executor    string            `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerTag   string            `yaml:"dockerTag" json:"dockerTag" mapstructure:"dockerTag"`
	DockerImage string            `yaml:"dockerImage" json:"dockerImage" mapstructure:"dockerImage"`
	Env         map[string]string `yaml:"env" json:"env" mapstructure:"-"` // note: we don't want users to specify run env vars by app config env vars
}

func (o Vunnel) Redact() {
	if o.Env == nil {
		return
	}
	for _, v := range o.Env {
		log.Redact(v)
	}
}

func DefaultVunnel() Vunnel {
	return Vunnel{
		Executor:    "docker",
		DockerTag:   "latest",
		DockerImage: "ghcr.io/anchore/vunnel",
	}
}

func (o *Vunnel) AddFlags(flags *pflag.FlagSet) {
}

func (o *Vunnel) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	// (none)

	// set default values for non-bound struct items
	v.SetDefault("vunnel.executor", o.Executor)
	v.SetDefault("vunnel.dockerTag", o.DockerTag)
	v.SetDefault("vunnel.dockerImage", o.DockerImage)
	v.SetDefault("vunnel.env", o.Env)

	return nil
}
