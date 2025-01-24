package process

import (
	"bytes"
	"fmt"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	v5 "github.com/anchore/grype-db/pkg/process/v5"
	v6 "github.com/anchore/grype-db/pkg/process/v6"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/entry"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDBv5 "github.com/anchore/grype/grype/db/v5"
	grypeDBv6 "github.com/anchore/grype/grype/db/v6"
)

type BuildConfig struct {
	SchemaVersion       int
	Directory           string
	States              provider.States
	Timestamp           time.Time
	IncludeCPEParts     []string
	InferNVDFixVersions bool
}

func Build(cfg BuildConfig) error {
	log.WithFields(
		"schema", cfg.SchemaVersion,
		"build-directory", cfg.Directory,
		"providers", cfg.States.Names()).
		Info("building database")

	processors, err := getProcessors(cfg)
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

func getProcessors(cfg BuildConfig) ([]data.Processor, error) {
	switch cfg.SchemaVersion {
	case grypeDBv5.SchemaVersion:
		return v5.Processors(v5.NewConfig(v5.WithCPEParts(cfg.IncludeCPEParts), v5.WithInferNVDFixVersions(cfg.InferNVDFixVersions))), nil
	case grypeDBv6.ModelVersion:
		return v6.Processors(v6.NewConfig(v6.WithCPEParts(cfg.IncludeCPEParts), v6.WithInferNVDFixVersions(cfg.InferNVDFixVersions))), nil
	default:
		return nil, fmt.Errorf("unable to create processor: unsupported schema version: %+v", cfg.SchemaVersion)
	}
}

func getWriter(schemaVersion int, dataAge time.Time, directory string, states provider.States) (data.Writer, error) {
	switch schemaVersion {
	case grypeDBv5.SchemaVersion:
		return v5.NewWriter(directory, dataAge, states)
	case grypeDBv6.ModelVersion:
		return v6.NewWriter(directory, states)
	default:
		return nil, fmt.Errorf("unable to create writer: unsupported schema version: %+v", schemaVersion)
	}
}

func build(results []providerResults, writer data.Writer, processors ...data.Processor) error {
	lastUpdate := time.Now()
	var totalRecords int
	for _, result := range results {
		totalRecords += int(result.count)
	}
	log.WithFields("total", humanize.Comma(int64(totalRecords))).Info("processing all records")

	var recordsProcessed int

	// for exponential moving average, choose an alpha between 0 and 1, where 1 biases towards the most recent sample
	// and 0 biases towards the average of all samples.
	rateWindow := newEMA(0.4)

	for _, result := range results {
		log.WithFields("provider", result.provider.Provider, "total", humanize.Comma(result.count)).Info("processing provider records")
		providerRecordsProcessed := 0
		recordsProcessedInStatusCycle := 0
		for opener := range result.openers {
			providerRecordsProcessed++
			recordsProcessed++
			recordsProcessedInStatusCycle++
			var processor data.Processor

			if time.Since(lastUpdate) > 3*time.Second {
				r := recordsPerSecond(recordsProcessedInStatusCycle, lastUpdate)
				rateWindow.Add(r)

				log.WithFields(
					"provider", fmt.Sprintf("%q %1.0f/s (%1.2f%%)", result.provider.Provider, r, percent(providerRecordsProcessed, int(result.count))),
					"overall", fmt.Sprintf("%1.2f%%", percent(recordsProcessed, totalRecords)),
					"eta", eta(recordsProcessed, totalRecords, rateWindow.Average()).String(),
				).Debug("status")
				lastUpdate = time.Now()
				recordsProcessedInStatusCycle = 0
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

type expMovingAverage struct {
	alpha float64
	value float64
	count int
}

func newEMA(alpha float64) *expMovingAverage {
	return &expMovingAverage{alpha: alpha}
}

func (e *expMovingAverage) Add(sample float64) {
	if e.count == 0 {
		e.value = sample // initialize with the first sample
	} else {
		e.value = e.alpha*sample + (1-e.alpha)*e.value
	}
	e.count++
}

func (e *expMovingAverage) Average() float64 {
	return e.value
}

func recordsPerSecond(idx int, lastUpdate time.Time) float64 {
	sec := time.Since(lastUpdate).Seconds()
	if sec == 0 {
		return 0
	}
	return float64(idx) / sec
}

func percent(idx, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(idx) / float64(total) * 100
}

func eta(idx, total int, rate float64) time.Duration {
	if rate == 0 {
		return 0
	}
	return time.Duration(float64(total-idx)/rate) * time.Second
}
