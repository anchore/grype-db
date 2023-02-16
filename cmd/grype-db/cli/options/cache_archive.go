package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &CacheArchive{}

type CacheArchive struct {
	// bound options
	Path string `yaml:"archive" json:"archive" mapstructure:"archive"`

	// unbound options
	// (none)
}

func DefaultCacheArchive() CacheArchive {
	return CacheArchive{
		Path: "./grype-db-cache.tar.gz",
	}
}

func (o *CacheArchive) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Path,
		"path", "", o.Path,
		"path to the grype-db cache archive",
	)
}

func (o *CacheArchive) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "cache.archive", flags.Lookup("path")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	// (none)

	return nil
}
