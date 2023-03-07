package options

import (
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Provider{}

type Provider struct {
	// bound options
	// (none)

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
		Root:   "./data",
		Vunnel: DefaultVunnel(),
		Configs: []provider.Config{
			{
				Identifier: provider.Identifier{
					Name: "alpine",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "amazon",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "debian",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "github",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "nvd",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "rhel",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "sles",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "ubuntu",
					Kind: provider.VunnelKind,
				},
			},
			{
				Identifier: provider.Identifier{
					Name: "wolfi",
					Kind: provider.VunnelKind,
				},
			},
		},
	}
}

func (o *Provider) AddFlags(flags *pflag.FlagSet) {
}

func (o *Provider) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	// (none)

	// set default values for non-bound struct items
	v.SetDefault("provider.root", o.Root)
	v.SetDefault("provider.configs", o.Configs)

	return nil
}
