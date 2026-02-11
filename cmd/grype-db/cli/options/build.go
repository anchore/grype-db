package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype/grype/db"
)

var _ Interface = &Build{}

type Build struct {
	DBLocation `yaml:",inline" mapstructure:",squash"` // note: json will anonymously embed the struct if there is no tag (like yaml inline)

	// bound options
	SkipValidation bool `yaml:"skip-validation" json:"skip-validation" mapstructure:"skip-validation"`
	SchemaVersion  int  `yaml:"schema-version" json:"schema-version" mapstructure:"schema-version"`
	BatchSize      int  `yaml:"batch-size" json:"batch-size" mapstructure:"batch-size"`

	// unbound options
	IncludeCPEParts      []string `yaml:"include-cpe-parts" json:"include-cpe-parts" mapstructure:"include-cpe-parts"`
	InferNVDFixVersions  bool     `yaml:"infer-nvd-fix-versions" json:"infer-nvd-fix-versions" mapstructure:"infer-nvd-fix-versions"`
	Hydrate              bool     `yaml:"hydrate" json:"hydrate" mapstructure:"hydrate"`
	FailOnMissingFixDate bool     `yaml:"fail-on-missing-fix-date" json:"fail-on-missing-fix-date" mapstructure:"fail-on-missing-fix-date"`
}

func DefaultBuild() Build {
	return Build{
		DBLocation:           DefaultDBLocation(),
		SkipValidation:       false,
		SchemaVersion:        db.DefaultSchemaVersion,
		BatchSize:            db.DefaultBatchSize,
		IncludeCPEParts:      []string{"a", "h", "o"},
		InferNVDFixVersions:  true,
		Hydrate:              false,
		FailOnMissingFixDate: false,
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

	flags.IntVarP(
		&o.BatchSize,
		"batch-size", "", o.BatchSize,
		"number of database operations to batch before flushing to disk (balances throughput with memory usage)",
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
	if err := Bind(v, "build.batch-size", flags.Lookup("batch-size")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("build.include-cpe-parts", o.IncludeCPEParts)
	v.SetDefault("build.infer-nvd-fix-versions", o.InferNVDFixVersions)
	v.SetDefault("build.hydrate", o.Hydrate)
	v.SetDefault("build.fail-on-missing-fix-date", o.FailOnMissingFixDate)

	return o.DBLocation.BindFlags(flags, v)
}
