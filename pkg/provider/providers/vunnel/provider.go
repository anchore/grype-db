package vunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/providers/external"
)

type Config struct {
	Config      string            `yaml:"config" json:"config" mapstructure:"config"`
	Executor    string            `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerImage string            `yaml:"dockerImage" json:"dockerImage" mapstructure:"dockerImage"`
	DockerTag   string            `yaml:"dockerTag" json:"dockerTag" mapstructure:"dockerTag"`
	Env         map[string]string `yaml:"env,omitempty" json:"env,omitempty" mapstructure:"env"`
}

func NewProvider(root string, id provider.Identifier, cfg Config) provider.Provider {
	return external.NewProvider(root, id,
		external.Config{
			Cmd:   getCommand(root, id, cfg),
			State: fmt.Sprintf("%s/metadata.json", id.Name),
			Env:   cfg.Env,
		},
	)
}

func getCommand(root string, id provider.Identifier, cfg Config) string {
	switch cfg.Executor {
	case "docker", "podman":
		dataRootCtr := root
		if !strings.HasPrefix(root, "/") {
			dataRootCtr = strings.TrimPrefix(root, "./")
		}

		dataRootHost, err := filepath.Abs(root)
		if err != nil {
			log.WithFields("error", err).Warn("unable to get absolute path for provider root directory, using relative path")
			dataRootHost = root
		}

		var cfgVol string
		if _, err := os.Stat(".vunnel.yaml"); !os.IsNotExist(err) {
			cwd, err := os.Getwd()
			if err != nil {
				log.WithFields("error", err, "provider", id.Name).Warn("unable to get current working directory, ignoring vunnel config")
			} else {
				cfgVol = fmt.Sprintf("-v %s/.vunnel.yaml:/.vunnel.yaml", cwd)
			}
		}

		var envStr string
		if cfg.Env != nil {
			for k, v := range cfg.Env {
				if strings.HasPrefix(v, "$") {
					v = os.Getenv(v[1:])
					// for safety, assume that all values from environment variables are sensitive
					log.Redact(v)
				}
				envStr += fmt.Sprintf("-e %s=%s ", k, v)
			}
		}

		return fmt.Sprintf("%s run --rm -t -v %s:/%s %s %s %s:%s run %s", cfg.Executor, dataRootHost, dataRootCtr, cfgVol, envStr, cfg.DockerImage, cfg.DockerTag, id.Name)
	}

	var cfgSection string
	if cfg.Config != "" {
		cfgSection = fmt.Sprintf("-c %s", cfg.Config)
	}

	return fmt.Sprintf("vunnel %s run %s", cfgSection, id.Name)
}
