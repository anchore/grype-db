package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Package{}

type Package struct {
	// bound options
	PublishBaseURL string `yaml:"publish-base-url" json:"publish-base-url" mapstructure:"publish-base-url"`

	// unbound options
	// (none)
}

func DefaultPackage() Package {
	return Package{
		PublishBaseURL: "https://localhost:8080/grype/databases",
	}
}

func (o *Package) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.PublishBaseURL,
		"publish-base-url", "u", o.PublishBaseURL,
		"the base URL used for reference in the listing.json index file",
	)
}

func (o *Package) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "package.publish-base-url", flags.Lookup("publish-base-url")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return nil
}
