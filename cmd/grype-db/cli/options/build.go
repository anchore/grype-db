package options

import (
	"github.com/anchore/grype-db/pkg/process"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Build{}

type Build struct {
	DBLocation `yaml:",inline" mapstructure:",squash"` // note: json will anonymously embed the struct if there is no tag (like yaml inline)

	// bound options
	SkipValidation bool `yaml:"skip-validation" json:"skip-validation" mapstructure:"skip-validation"`
	SchemaVersion  int  `yaml:"schema-version" json:"schema-version" mapstructure:"schema-version"`

	// unbound options
	// (none)
}

func DefaultBuild() Build {
	return Build{
		DBLocation:     DefaultDBLocation(),
		SkipValidation: false,
		SchemaVersion:  process.DefaultSchemaVersion,
	}
}

func (o *Build) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.SkipValidation,
		"skip-validation", "", o.SkipValidation,
		"skip validation of the provider state",
	)

	flags.IntVarP(
		&o.SchemaVersion,
		"schema", "s", o.SchemaVersion,
		"DB Schema version to build for",
	)

	o.DBLocation.AddFlags(flags)
}

func (o *Build) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "build.skip-validation", flags.Lookup("skip-validation")); err != nil {
		return err
	}
	if err := Bind(v, "build.schema-version", flags.Lookup("schema")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return o.DBLocation.BindFlags(flags, v)
}
