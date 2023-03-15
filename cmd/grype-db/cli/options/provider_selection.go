package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Provider{}

type Selection struct {
	// bound options
	IncludeFilter []string `yaml:"include-filter" json:"include-filter" mapstructure:"include-filter"`

	// unbound options
	// (none)
}

func DefaultSelection() Selection {
	return Selection{}
}

func (o *Selection) AddFlags(flags *pflag.FlagSet) {
	// bound options
	flags.StringArrayVarP(
		&o.IncludeFilter,
		"provider-name", "p", o.IncludeFilter,
		"one or more provider names to filter building a DB for (default: empty = all)",
	)

	// unbound options
	// (none)
}

func (o *Selection) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "provider.include-filter", flags.Lookup("provider-name")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return nil
}
