package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/internal/redact"
)

var _ Interface = &Vunnel{}

type Vunnel struct {
	// bound options
	// (none)

	// unbound options
	Config           string            `yaml:"config" json:"config" mapstructure:"config"`
	Executor         string            `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerTag        string            `yaml:"docker-tag" json:"docker-tag" mapstructure:"docker-tag"`
	DockerImage      string            `yaml:"docker-image" json:"docker-image" mapstructure:"docker-image"`
	GenerateConfigs  bool              `yaml:"generate-configs" json:"generate-configs" mapstructure:"generate-configs"`
	ExcludeProviders []string          `yaml:"exclude-providers" json:"exclude-providers" mapstructure:"exclude-providers"`
	Env              map[string]string `yaml:"env" json:"env" mapstructure:"-"` // note: we don't want users to specify run env vars by app config env vars
}

func (o Vunnel) Redact() {
	if o.Env == nil {
		return
	}
	for _, v := range o.Env {
		redact.Add(v)
	}
}

func DefaultVunnel() Vunnel {
	return Vunnel{
		Executor:        "docker",
		DockerTag:       "latest",
		GenerateConfigs: false,
		ExcludeProviders: []string{
			// rhel will cover centos data within grype via namespace-distro remapping
			"centos",
		},
		DockerImage: "ghcr.io/anchore/vunnel",
	}
}

func (o *Vunnel) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.GenerateConfigs,
		"generate-providers-from-vunnel", "g", o.GenerateConfigs,
		"Generate provider configs from 'vunnel list' output",
	)
}

func (o *Vunnel) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "vunnel.generate-configs", flags.Lookup("generate-providers-from-vunnel")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("vunnel.config", o.Config)
	v.SetDefault("vunnel.executor", o.Executor)
	v.SetDefault("vunnel.docker-tag", o.DockerTag)
	v.SetDefault("vunnel.docker-image", o.DockerImage)
	v.SetDefault("vunnel.exclude-providers", o.ExcludeProviders)
	v.SetDefault("vunnel.env", o.Env)

	return nil
}
