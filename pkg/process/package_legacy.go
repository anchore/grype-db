package process

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype/grype/db/legacy/distribution"
	grypeDBLegacy "github.com/anchore/grype/grype/db/v5"
	grypeDBLegacyStore "github.com/anchore/grype/grype/db/v5/store"
)

func packageLegacyDB(dbDir, publishBaseURL, overrideArchiveExtension string) error { //nolint:funlen
	log.WithFields("from", dbDir, "url", publishBaseURL, "extension-override", overrideArchiveExtension).Info("packaging database")

	fs := afero.NewOsFs()
	metadata, err := distribution.NewMetadataFromDir(fs, dbDir)
	if err != nil {
		return err
	}

	if metadata == nil {
		return fmt.Errorf("no metadata found in %q", dbDir)
	}

	s, err := grypeDBLegacyStore.New(filepath.Join(dbDir, grypeDBLegacy.VulnerabilityStoreFileName), false)
	if err != nil {
		return fmt.Errorf("unable to open vulnerability store: %w", err)
	}

	id, err := s.GetID()
	if err != nil {
		return fmt.Errorf("unable to get vulnerability store ID: %w", err)
	}

	if id.SchemaVersion != metadata.Version {
		return fmt.Errorf("metadata version %d does not match vulnerability store version %d", metadata.Version, id.SchemaVersion)
	}

	u, err := url.Parse(publishBaseURL)
	if err != nil {
		return err
	}

	// we need a well-ordered string to append to the archive name to ensure uniqueness (to avoid overwriting
	// existing archives in the CDN) as well as to ensure that multiple archives created in the same day are
	// put in the correct order in the listing file. The DB timestamp represents the age of the data in the DB
	// not when the DB was created. The trailer represents the time the DB was packaged.
	trailer := fmt.Sprintf("%d", secondsSinceEpoch())

	// TODO (alex): supporting tar.zst
	// var extension = "tar.zst"
	var extension = "tar.gz"

	if overrideArchiveExtension != "" {
		extension = strings.TrimLeft(overrideArchiveExtension, ".")
	}
	// TODO (alex): supporting tar.zst
	// else if metadata.Version < 5 {
	// 	extension = "tar.gz"
	// }

	var found bool
	for _, valid := range []string{"tar.zst", "tar.gz"} {
		if valid == extension {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("invalid archive extension %q", extension)
	}

	// we attach a random value at the end of the file name to prevent from overwriting DBs in S3 that are already
	// cached in the CDN. Ideally this would be based off of the archive checksum but a random string is simpler.
	tarName := fmt.Sprintf(
		"vulnerability-db_v%d_%s_%s.%s",
		metadata.Version,
		metadata.Built.Format(time.RFC3339),
		trailer,
		extension,
	)
	tarPath := path.Join(dbDir, tarName)

	if err := populateTar(tarPath); err != nil {
		return err
	}

	log.WithFields("path", tarPath).Info("created database archive")

	entry, err := distribution.NewListingEntryFromArchive(fs, *metadata, tarPath, u)
	if err != nil {
		return fmt.Errorf("unable to create listing entry from archive: %w", err)
	}

	listing := distribution.NewListing(entry)
	listingPath := path.Join(dbDir, distribution.ListingFileName)
	if err = listing.Write(listingPath); err != nil {
		return err
	}

	log.WithFields("path", listingPath).Debug("created initial listing file")

	return nil
}

func secondsSinceEpoch() int64 {
	return time.Now().UTC().Unix()
}
