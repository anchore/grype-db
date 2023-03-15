package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Pull{}

type Pull struct {
	// bound options
	Parallelism int `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`

	// unbound options
	// (none)
}

func DefaultPull() Pull {
	return Pull{
		Parallelism: 4,
	}
}

func (o *Pull) AddFlags(flags *pflag.FlagSet) {
	flags.IntVarP(
		&o.Parallelism,
		"parallelism", "", o.Parallelism,
		"number of vulnerability providers to update concurrently",
	)
}

func (o *Pull) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "pull.parallelism", flags.Lookup("parallelism")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return nil
}
