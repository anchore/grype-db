package process

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/internal/tarutil"
	"github.com/anchore/grype-db/pkg/provider"
	grypeDBLegacyDistribution "github.com/anchore/grype/grype/db/legacy/distribution"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6Distribution "github.com/anchore/grype/grype/db/v6/distribution"
)

func Package(dbDir, publishBaseURL, overrideArchiveExtension string) error {
	// check if metadata file exists, if so, then this
	if _, err := os.Stat(filepath.Join(dbDir, grypeDBLegacyDistribution.MetadataFileName)); os.IsNotExist(err) {
		return packageDB(dbDir, overrideArchiveExtension)
	}
	return packageLegacyDB(dbDir, publishBaseURL, overrideArchiveExtension)
}

func packageDB(dbDir, overrideArchiveExtension string) error {
	extension, err := resolveExtension(overrideArchiveExtension)
	if err != nil {
		return err
	}
	log.WithFields("from", dbDir, "extension", extension).Info("packaging database")

	s, err := v6.NewReader(v6.Config{DBDirPath: dbDir})
	if err != nil {
		return fmt.Errorf("unable to open vulnerability store: %w", err)
	}

	metadata, err := s.GetDBMetadata()
	if err != nil || metadata == nil {
		return fmt.Errorf("unable to get vulnerability store metadata: %w", err)
	}

	if metadata.Model != v6.ModelVersion {
		return fmt.Errorf("metadata model %d does not match vulnerability store model %d", v6.ModelVersion, metadata.Model)
	}

	providerModels, err := s.AllProviders()
	if err != nil {
		return fmt.Errorf("unable to get all providers: %w", err)
	}

	if len(providerModels) == 0 {
		return fmt.Errorf("no providers found in the vulnerability store")
	}

	eldest, err := toProviders(providerModels).EarliestTimestamp()
	if err != nil {
		return err
	}

	// output archive vulnerability-db_VERSION_OLDESTDATADATE_BUILTEPOCH.tar.gz, where:
	// - VERSION: schema version in the form of v#.#.#
	// - OLDESTDATADATE: RFC3338 formatted value of the oldest date capture date found for all contained providers
	// - BUILTEPOCH: linux epoch formatted value of the database metadata built field
	tarName := fmt.Sprintf(
		"vulnerability-db_v%s_%s_%d.%s",
		fmt.Sprintf("%d.%d.%d", metadata.Model, metadata.Revision, metadata.Addition),
		eldest.UTC().Format(time.RFC3339),
		metadata.BuildTimestamp.Unix(),
		extension,
	)

	tarPath := filepath.Join(dbDir, tarName)

	if err := populateTar(tarPath); err != nil {
		return err
	}

	log.WithFields("path", tarPath).Info("created database archive")

	return writeLatestDocument(tarPath, *metadata)
}

func toProviders(states []v6.Provider) provider.States {
	var result provider.States
	for _, state := range states {
		result = append(result, provider.State{
			Provider:  state.ID,
			Timestamp: *state.DateCaptured,
		})
	}
	return result
}

func resolveExtension(overrideArchiveExtension string) (string, error) {
	var extension = "tar.zst"

	if overrideArchiveExtension != "" {
		extension = strings.TrimLeft(overrideArchiveExtension, ".")
	}

	var found bool
	for _, valid := range []string{"tar.zst", "tar.xz", "tar.gz"} {
		if valid == extension {
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("unsupported archive extension %q", extension)
	}
	return extension, nil
}

var listingFiles = strset.New("listing.json", "latest.json", "history.json")

func populateTar(tarPath string) error {
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("unable to get CWD: %w", err)
	}

	dbDir, tarName := filepath.Split(tarPath)

	if dbDir != "" {
		if err = os.Chdir(dbDir); err != nil {
			return fmt.Errorf("unable to cd to build dir: %w", err)
		}

		defer func() {
			if err = os.Chdir(originalDir); err != nil {
				log.Errorf("unable to cd to original dir: %v", err)
			}
		}()
	}

	fileInfos, err := os.ReadDir("./")
	if err != nil {
		return fmt.Errorf("unable to list db directory: %w", err)
	}

	var files []string
	for _, fi := range fileInfos {
		if !listingFiles.Has(fi.Name()) && !strings.Contains(fi.Name(), ".tar.") {
			files = append(files, fi.Name())
		}
	}

	if err = tarutil.PopulateWithPaths(tarName, files...); err != nil {
		return fmt.Errorf("unable to create db archive: %w", err)
	}

	return nil
}

func writeLatestDocument(tarPath string, metadata v6.DBMetadata) error {
	archive, err := v6Distribution.NewArchive(tarPath, *metadata.BuildTimestamp, metadata.Model, metadata.Revision, metadata.Addition)
	if err != nil || archive == nil {
		return fmt.Errorf("unable to create archive: %w", err)
	}

	doc := v6Distribution.NewLatestDocument(*archive)
	if doc == nil {
		return errors.New("unable to create latest document")
	}

	dbDir := filepath.Dir(tarPath)

	latestPath := path.Join(dbDir, v6Distribution.LatestFileName)

	fh, err := os.OpenFile(latestPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to create latest file: %w", err)
	}

	if err = doc.Write(fh); err != nil {
		return fmt.Errorf("unable to write latest document: %w", err)
	}
	return nil
}
