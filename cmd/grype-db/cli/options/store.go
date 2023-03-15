package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Store{}

type Store struct {
	// bound options
	// (none)

	// unbound options
	Root string `yaml:"root" json:"root" mapstructure:"root"`
}

func DefaultStore() Store {
	return Store{
		Root: "./data",
	}
}

func (o *Store) AddFlags(flags *pflag.FlagSet) {
	// bound options
	// (none)

	// unbound options
	// (none)
}

func (o *Store) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	// (none)

	// set default values for non-bound struct items
	v.SetDefault("provider.root", o.Root)

	return nil
}
