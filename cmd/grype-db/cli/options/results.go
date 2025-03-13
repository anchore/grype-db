package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Results{}

type Results struct {
	ResultsOnly bool `yaml:"results-only" json:"results-only" mapstructure:"results-only"`
}

func (r Results) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&r.ResultsOnly,
		"results-only", "r", r.ResultsOnly,
		"only backup the results and ignore the input directories (default: false)",
	)
}

func (r Results) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return Bind(v, "results.results-only", flags.Lookup("results-only"))
}

func DefaultResults() Results {
	return Results{ResultsOnly: false}
}
