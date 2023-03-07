package process

import (
	"bytes"
	"fmt"
	"time"

	"github.com/dustin/go-humanize"

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
)

type BuildConfig struct {
	SchemaVersion int
	Directory     string
	States        provider.States
	Timestamp     time.Time
}

func Build(cfg BuildConfig) error {
	log.WithFields("schema", cfg.SchemaVersion, "build-directory", cfg.Directory, "providers", cfg.States.Names()).Info("building DB")

	processors, err := getProcessors(cfg.SchemaVersion)
	if err != nil {
		return err
	}

	writer, err := getWriter(cfg.SchemaVersion, cfg.Timestamp, cfg.Directory)
	if err != nil {
		return err
	}

	var openers []openerEntry
	for _, sd := range cfg.States {
		sdOpeners, count, err := entry.Openers(sd.Store, sd.ResultPaths())
		if err != nil {
			return fmt.Errorf("failed to open provider result files: %w", err)
		}
		openers = append(openers, openerEntry{
			openers: sdOpeners,
			name:    sd.Provider,
			count:   count,
		})
	}

	if err := build(mergeOpeners(openers), writer, processors...); err != nil {
		return err
	}

	return writer.Close()
}

type openerEntry struct {
	openers <-chan entry.Opener
	name    string
	count   int64
}

func mergeOpeners(entries []openerEntry) <-chan entry.Opener {
	out := make(chan entry.Opener)
	go func() {
		defer close(out)
		for _, e := range entries {
			log.WithFields("provider", e.name, "records", humanize.Comma(e.count)).Debug("writing to DB")

			for opener := range e.openers {
				out <- opener
			}
		}
	}()
	return out
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
	default:
		return nil, fmt.Errorf("unable to create processor: unsupported schema version: %+v", schemaVersion)
	}
}

func getWriter(schemaVersion int, dataAge time.Time, directory string) (data.Writer, error) {
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
		return v5.NewWriter(directory, dataAge)
	default:
		return nil, fmt.Errorf("unable to create writer: unsupported schema version: %+v", schemaVersion)
	}
}

func build(openers <-chan entry.Opener, writer data.Writer, processors ...data.Processor) error {
	for opener := range openers {
		log.WithFields("entry", opener.String()).Tracef("processing")
		var processor data.Processor

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

		entries, err := processor.Process(bytes.NewReader(envelope.Item))
		if err != nil {
			return fmt.Errorf("failed to process cache entry %q: %w", opener.String(), err)
		}

		if err := writer.Write(entries...); err != nil {
			return fmt.Errorf("failed to write records to the DB for cache entry %q: %w", opener.String(), err)
		}
	}

	log.Debugf("wrote all provider state")

	return nil
}
