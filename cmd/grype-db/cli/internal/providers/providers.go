package providers

import (
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/providers/external"
	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/providers/vunnel"
	"github.com/anchore/grype/grype/db/data/provider"
)

var ErrNoProviders = fmt.Errorf("no providers configured")

func New(root string, vCfg vunnel.Config, cfgs ...Config) (provider.Providers, error) {
	var providers []provider.Provider

	if vCfg.GenerateConfigs {
		generatedNames, err := vunnel.GenerateNames(root, vCfg)
		if err != nil {
			return nil, fmt.Errorf("unable to generate vunnel providers: %w", err)
		}
		for _, name := range generatedNames {
			cfgs = append(cfgs, Config{
				Identifier: Identifier{
					Name: name,
					Kind: VunnelKind,
				},
			})
		}
	}

	if len(cfgs) == 0 {
		return nil, ErrNoProviders
	}

	for _, cfg := range cfgs {
		p, err := newProvider(root, vCfg, cfg)
		if err != nil {
			return nil, err
		}
		if p.Name() == "nvd" {
			// it is important that NVD is processed first since other providers depend on the severity information from these records
			providers = append([]provider.Provider{p}, providers...)
		} else {
			providers = append(providers, p)
		}
	}

	return providers, nil
}

func newProvider(root string, vCfg vunnel.Config, cfg Config) (provider.Provider, error) {
	switch cfg.Kind {
	case VunnelKind, "": // note: this is the default
		return vunnel.NewProvider(root, cfg.Identifier.Name, vCfg), nil
	case ExternalKind:
		var c external.Config
		if err := mapstructure.Decode(cfg.Config, &c); err != nil {
			return nil, fmt.Errorf("failed to decode external provider config: %w", err)
		}
		return external.NewProvider(root, cfg.Identifier.Name, c), nil
	case InternalKind:
		return newInternal(root, cfg)
	default:
		return nil, fmt.Errorf("unknown provider kind %q", cfg.Kind)
	}
}

func newInternal(_ string, _ Config) (provider.Provider, error) {
	return nil, fmt.Errorf("internal providers not yet implemented")
}
