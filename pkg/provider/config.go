package provider

type Collection struct {
	Root      string
	Providers []Provider
}

type Config struct {
	Identifier `json:",inline" yaml:",inline" mapstructure:",squash"`
	Config     interface{} `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

type Identifier struct {
	Name string `yaml:"name" json:"name" mapstructure:"name"`
	Kind Kind   `yaml:"kind,omitempty" json:"kind" mapstructure:"kind"`
}
