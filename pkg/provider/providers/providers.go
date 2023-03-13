package providers

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/providers/external"
	"github.com/anchore/grype-db/pkg/provider/providers/vunnel"
)

var ErrNoProviders = fmt.Errorf("no providers configured")

func New(root string, vCfg vunnel.Config, cfgs ...provider.Config) (provider.Providers, error) {
	var providers []provider.Provider

	if vCfg.GenerateConfigs {
		generatedCfgs, err := generateConfigs(vCfg.ExcludeProviders)
		if err != nil {
			return nil, fmt.Errorf("unable to generate vunnel providers: %w", err)
		}
		cfgs = append(cfgs, generatedCfgs...)
	}

	if len(cfgs) == 0 {
		return nil, ErrNoProviders
	}

	for _, cfg := range cfgs {
		p, err := newProvider(root, vCfg, cfg)
		if err != nil {
			return nil, err
		}
		if p.ID().Name == "nvd" {
			// it is important that NVD is processed first since other providers depend on the severity information from these records
			providers = append([]provider.Provider{p}, providers...)
		} else {
			providers = append(providers, p)
		}
	}

	return providers, nil
}

func generateConfigs(exclude []string) ([]provider.Config, error) {
	out, err := exec.Command("vunnel", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("unable to execute vunnel list: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	excludeSet := strset.New(exclude...)

	var cfgs []provider.Config
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if excludeSet.Has(line) {
			log.WithFields("provider", line).Trace("skipping config")
			continue
		}
		log.WithFields("provider", line).Trace("including config")
		cfgs = append(cfgs, provider.Config{
			Identifier: provider.Identifier{
				Name: line,
				Kind: provider.VunnelKind,
			},
		})
	}

	return cfgs, nil
}

func newProvider(root string, vCfg vunnel.Config, cfg provider.Config) (provider.Provider, error) {
	switch cfg.Kind {
	case provider.VunnelKind, "": // note: this is the default
		return vunnel.NewProvider(root, cfg.Identifier, vCfg), nil
	case provider.ExternalKind:
		var c external.Config
		if err := mapstructure.Decode(cfg.Config, &c); err != nil {
			return nil, fmt.Errorf("failed to decode external provider config: %w", err)
		}
		return external.NewProvider(root, cfg.Identifier, c), nil
	case provider.InternalKind:
		return newInternal(root, cfg)
	default:
		return nil, fmt.Errorf("unknown provider kind %q", cfg.Kind)
	}
}

func newInternal(_ string, _ provider.Config) (provider.Provider, error) {
	return nil, fmt.Errorf("internal providers not yet implemented")
}
