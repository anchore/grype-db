package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/pkg/provider"
)

var _ Interface = &Provider{}

type Provider struct {
	// bound options
	IncludeFilter []string `yaml:"include-filter" json:"include-filter" mapstructure:"include-filter"`

	// unbound options
	Root    string            `yaml:"root" json:"root" mapstructure:"root"`
	Vunnel  Vunnel            `yaml:"vunnel" json:"vunnel" mapstructure:"vunnel"`
	Configs []provider.Config `yaml:"configs" json:"configs" mapstructure:"configs"`
}

func (o Provider) Redact() {
	o.Vunnel.Redact()
	for _, v := range o.Configs {
		v.Redact()
	}
}

func DefaultProvider() Provider {
	return Provider{
		Root:    "./data",
		Vunnel:  DefaultVunnel(),
		Configs: nil,
	}
}

func (o *Provider) AddFlags(flags *pflag.FlagSet) {
	// bound options
	flags.StringArrayVarP(
		&o.IncludeFilter,
		"provider-name", "p", o.IncludeFilter,
		"one or more provider names to filter building a DB for (default: empty = all)",
	)

	// unbound options

	// nested options
	o.Vunnel.AddFlags(flags)
}

func (o *Provider) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "provider.include-filter", flags.Lookup("provider-name")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("provider.root", o.Root)
	v.SetDefault("provider.configs", o.Configs)

	// nested options
	return o.Vunnel.BindFlags(flags, v)
}
