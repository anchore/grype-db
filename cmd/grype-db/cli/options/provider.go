package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/pull"
)

var _ Interface = &Provider{}

type Provider struct {
	// bound options
	Selection `yaml:",inline" mapstructure:",squash"`

	// unbound options
	Store   `yaml:",inline" mapstructure:",squash"`
	Vunnel  Vunnel                   `yaml:"vunnel" json:"vunnel" mapstructure:"vunnel"`
	Configs []pull.ProviderRunConfig `yaml:"configs" json:"configs" mapstructure:"configs"`
}

func (o *Provider) Redact() {
	o.Vunnel.Redact()
	for _, v := range o.Configs {
		v.Redact()
	}
}

func DefaultProvider() Provider {
	return Provider{
		Store:     DefaultStore(),
		Vunnel:    DefaultVunnel(),
		Selection: DefaultSelection(),
		Configs:   nil,
	}
}

func (o *Provider) AddFlags(flags *pflag.FlagSet) {
	// bound options
	// (none)

	// unbound options
	// (none)

	// nested options
	o.Vunnel.AddFlags(flags)
	o.Store.AddFlags(flags)
	o.Selection.AddFlags(flags)
}

func (o *Provider) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	// (none)

	// set default values for non-bound struct items
	v.SetDefault("provider.configs", o.Configs)

	// nested options
	if err := o.Vunnel.BindFlags(flags, v); err != nil {
		return err
	}
	if err := o.Selection.BindFlags(flags, v); err != nil {
		return err
	}
	return o.Store.BindFlags(flags, v)
}
