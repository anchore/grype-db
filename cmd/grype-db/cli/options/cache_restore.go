package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &CacheRestore{}

type CacheRestore struct {
	// bound options
	DeleteExisting bool `yaml:"delete-existing" json:"delete-existing" mapstructure:"delete-existing"`

	// unbound options
	// (none)
}

func DefaultCacheRestore() CacheRestore {
	return CacheRestore{
		DeleteExisting: false,
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
	// (none)

	return nil
}
