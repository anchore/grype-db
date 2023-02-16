package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &DBLocation{}

type DBLocation struct {
	// bound options
	Directory string `yaml:"dir" json:"dir" mapstructure:"dir"`

	// unbound options
	// (none)
}

func DefaultDBLocation() DBLocation {
	return DBLocation{
		Directory: "./build",
	}
}

func (o *DBLocation) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Directory,
		"dir", "d", o.Directory,
		"directory where the database is written",
	)
}

func (o *DBLocation) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "build.dir", flags.Lookup("dir")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return nil
}
