package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &FilterProviders{}

type FilterProviders struct {
	// bound options
	ProviderNames []string `yaml:"provider-names" json:"provider-names" mapstructure:"provider-names"`

	// unbound options
	// (none)
}

func DefaultFilterProviders() FilterProviders {
	return FilterProviders{}
}

func (o *FilterProviders) AddFlags(flags *pflag.FlagSet) {
	flags.StringArrayVarP(
		&o.ProviderNames,
		"provider-name", "p", o.ProviderNames,
		"one or more provider names to manipulate data for (default: empty = all)",
	)
}

func (o *FilterProviders) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "filter.provider-names", flags.Lookup("provider-name")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return nil
}
