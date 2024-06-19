package process

import (
	"bytes"
	"fmt"
	v6 "github.com/anchore/grype-db/pkg/process/v6"
	"time"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	v1 "github.com/anchore/grype-db/pkg/process/v1"
	v2 "github.com/anchore/grype-db/pkg/process/v2"
	v3 "github.com/anchore/grype-db/pkg/process/v3"
	v4 "github.com/anchore/grype-db/pkg/process/v4"
	v5 "github.com/anchore/grype-db/pkg/process/v5"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/entry"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDBv1 "github.com/anchore/grype/grype/db/v1"
	grypeDBv2 "github.com/anchore/grype/grype/db/v2"
	grypeDBv3 "github.com/anchore/grype/grype/db/v3"
	grypeDBv4 "github.com/anchore/grype/grype/db/v4"
	grypeDBv5 "github.com/anchore/grype/grype/db/v5"
	grypeDBv6 "github.com/anchore/grype/grype/db/v6"
)

type BuildConfig struct {
	SchemaVersion int
	Directory     string
	States        provider.States
	Timestamp     time.Time
}

func Build(cfg BuildConfig) error {
	log.WithFields(
		"schema", cfg.SchemaVersion,
		"build-directory", cfg.Directory,
		"providers", cfg.States.Names()).
		Info("building database")

	processors, err := getProcessors(cfg.SchemaVersion)
	if err != nil {
		return err
	}

	writer, err := getWriter(cfg.SchemaVersion, cfg.Timestamp, cfg.Directory, cfg.States)
	if err != nil {
		return err
	}

	var openers []providerResults
	for _, sd := range cfg.States {
		sdOpeners, count, err := entry.Openers(sd.Store, sd.ResultPaths())
		if err != nil {
			return fmt.Errorf("failed to open provider result files: %w", err)
		}
		openers = append(openers, providerResults{
			openers:  sdOpeners,
			provider: sd,
			count:    count,
		})
	}

	if err := build(openers, writer, processors...); err != nil {
		return err
	}

	return writer.Close()
}

type providerResults struct {
	openers  <-chan entry.Opener
	provider provider.State
	count    int64
}

func getProcessors(schemaVersion int) ([]data.Processor, error) {
	switch schemaVersion {
	case grypeDBv1.SchemaVersion:
		return v1.Processors(), nil
	case grypeDBv2.SchemaVersion:
		return v2.Processors(), nil
	case grypeDBv3.SchemaVersion:
		return v3.Processors(), nil
	case grypeDBv4.SchemaVersion:
		return v4.Processors(), nil
	case grypeDBv5.SchemaVersion:
		return v5.Processors(), nil
	case grypeDBv6.SchemaVersion:
		return v6.Processors(), nil
	default:
		return nil, fmt.Errorf("unable to create processor: unsupported schema version: %+v", schemaVersion)
	}
}

func getWriter(schemaVersion int, dataAge time.Time, directory string, states provider.States) (data.Writer, error) {
	switch schemaVersion {
	case grypeDBv1.SchemaVersion:
		return v1.NewWriter(directory, dataAge)
	case grypeDBv2.SchemaVersion:
		return v2.NewWriter(directory, dataAge)
	case grypeDBv3.SchemaVersion:
		return v3.NewWriter(directory, dataAge)
	case grypeDBv4.SchemaVersion:
		return v4.NewWriter(directory, dataAge)
	case grypeDBv5.SchemaVersion:
		return v5.NewWriter(directory, dataAge, states)
	case grypeDBv6.SchemaVersion:
		return v6.NewWriter(directory, dataAge, states)
	default:
		return nil, fmt.Errorf("unable to create writer: unsupported schema version: %+v", schemaVersion)
	}
}

func build(results []providerResults, writer data.Writer, processors ...data.Processor) error {
	for _, result := range results {
		log.WithFields("provider", result.provider.Provider, "count", result.count).Debug("processing provider records")
		idx := 0
		for opener := range result.openers {
			idx++
			log.WithFields("entry", opener.String()).Tracef("processing")
			var processor data.Processor

			if idx%1000 == 0 {
				log.WithFields("provider", result.provider.Provider, "count", result.count, "processed", idx).Debug("processing provider records")
			}

			f, err := opener.Open()
			if err != nil {
				return fmt.Errorf("failed to open cache entry %q: %w", opener.String(), err)
			}
			envelope, err := unmarshal.Envelope(f)
			if err != nil {
				return fmt.Errorf("failed to unmarshal cache entry %q: %w", opener.String(), err)
			}

			for _, candidate := range processors {
				if candidate.IsSupported(envelope.Schema) {
					processor = candidate
					log.WithFields("schema", envelope.Schema).Trace("matched with processor")
					break
				}
			}
			if processor == nil {
				log.WithFields("schema", envelope.Schema).Warnf("schema is not implemented for any processor. Dropping item")
				continue
			}

			entries, err := processor.Process(bytes.NewReader(envelope.Item), result.provider)
			if err != nil {
				return fmt.Errorf("failed to process cache entry %q: %w", opener.String(), err)
			}

			if err := writer.Write(entries...); err != nil {
				return fmt.Errorf("failed to write records to the DB for cache entry %q: %w", opener.String(), err)
			}
		}
	}

	log.Debugf("wrote all provider state")

	return nil
}
