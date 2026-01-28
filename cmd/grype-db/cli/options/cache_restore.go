package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &CacheRestore{}

type CacheRestore struct {
	// bound options
	DeleteExisting bool   `yaml:"delete-existing" json:"delete-existing" mapstructure:"delete-existing"`
	MaxFileSize    string `yaml:"max-file-size" json:"max-file-size" mapstructure:"max-file-size"`

	// unbound options
	// (none)
}

func DefaultCacheRestore() CacheRestore {
	return CacheRestore{
		DeleteExisting: false,
		MaxFileSize:    "25GB",
	}
}

func (o *CacheRestore) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.DeleteExisting,
		"delete-existing", "d", o.DeleteExisting,
		"delete existing cache before restoring from backup",
	)
}

func (o *CacheRestore) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for bound struct items
	if err := Bind(v, "restore.delete-existing", flags.Lookup("delete-existing")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("restore.max-file-size", o.MaxFileSize)

	return nil
}
