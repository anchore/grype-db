package v6

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/data"
	dataV6 "github.com/anchore/grype-db/pkg/data/v6"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath        string
	store         grypeDB.ReadWriter
	providerCache map[string]grypeDB.Provider
	states        provider.States
	severityCache map[string]grypeDB.Severity
}

type ProviderMetadata struct {
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Name              string    `json:"name"`
	LastSuccessfulRun time.Time `json:"lastSuccessfulRun"`
}

func NewWriter(directory string, states provider.States) (data.Writer, error) {
	cfg := grypeDB.Config{
		DBDirPath: directory,
	}
	s, err := grypeDB.NewWriter(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	if err := s.SetDBMetadata(); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	w := &writer{
		dbPath:        cfg.DBFilePath(),
		providerCache: make(map[string]grypeDB.Provider),
		store:         s,
		states:        states,
		severityCache: make(map[string]grypeDB.Severity),
	}

	// Populate initial OS and package specifier overrides
	if err := w.populateInitialOverrides(); err != nil {
		return nil, fmt.Errorf("unable to populate initial overrides: %w", err)
	}

	return w, nil
}

// populateInitialOverrides populates the database with initial OS and package specifier overrides
func (w *writer) populateInitialOverrides() error {
	type lowLevelReader interface {
		GetDB() *gorm.DB
	}

	db := w.store.(lowLevelReader).GetDB()

	// Populate OS specifier overrides
	osOverrides := dataV6.KnownOperatingSystemSpecifierOverrides()
	for i := range osOverrides {
		override := &osOverrides[i]

		// Use FirstOrCreate to avoid constraint violations when data already exists
		if err := db.FirstOrCreate(override, grypeDB.OperatingSystemSpecifierOverride{
			Alias:          override.Alias,
			Version:        override.Version,
			VersionPattern: override.VersionPattern,
			Codename:       override.Codename,
		}).Error; err != nil {
			return fmt.Errorf("unable to populate OS override %s: %w", override.Alias, err)
		}
	}

	// Populate package specifier overrides
	packageOverrides := dataV6.KnownPackageSpecifierOverrides()
	for i := range packageOverrides {
		override := &packageOverrides[i]

		// Use FirstOrCreate to avoid constraint violations when data already exists
		if err := db.FirstOrCreate(override, grypeDB.PackageSpecifierOverride{
			Ecosystem: override.Ecosystem,
		}).Error; err != nil {
			return fmt.Errorf("unable to populate package override %s: %w", override.Ecosystem, err)
		}
	}

	log.Info("populated initial OS and package specifier overrides")
	return nil
}

func (w writer) Write(entries ...data.Entry) error {
	for _, entry := range entries {
		if entry.DBSchemaVersion != grypeDB.ModelVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", grypeDB.ModelVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case transformers.RelatedEntries:
			if err := w.writeEntry(row); err != nil {
				return fmt.Errorf("unable to write entry to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

func (w *writer) writeEntry(entry transformers.RelatedEntries) error {
	log.WithFields("entry", entry.String()).Trace("writing entry")

	if entry.VulnerabilityHandle != nil {
		w.fillInMissingSeverity(entry.VulnerabilityHandle)

		if err := w.store.AddVulnerabilities(entry.VulnerabilityHandle); err != nil {
			return fmt.Errorf("unable to write vulnerability to store: %w", err)
		}
	}

	if entry.Provider != nil {
		if err := w.store.AddProvider(*entry.Provider); err != nil {
			return fmt.Errorf("unable to write provider to store: %w", err)
		}
	}

	for i := range entry.Related {
		related := entry.Related[i]
		switch row := related.(type) {
		case grypeDB.AffectedPackageHandle:
			if entry.VulnerabilityHandle != nil {
				row.VulnerabilityID = entry.VulnerabilityHandle.ID
			} else {
				log.WithFields("package", row.Package).Warn("affected package entry does not have a vulnerability ID")
			}
			if err := w.store.AddAffectedPackages(&row); err != nil {
				return fmt.Errorf("unable to write affected-package to store: %w", err)
			}
		case grypeDB.AffectedCPEHandle:
			if entry.VulnerabilityHandle != nil {
				row.VulnerabilityID = entry.VulnerabilityHandle.ID
			} else {
				log.WithFields("cpe", row.CPE).Warn("affected CPE entry does not have a vulnerability ID")
			}
			if err := w.store.AddAffectedCPEs(&row); err != nil {
				return fmt.Errorf("unable to write affected-cpe to store: %w", err)
			}
		case grypeDB.KnownExploitedVulnerabilityHandle:
			if err := w.store.AddKnownExploitedVulnerabilities(&row); err != nil {
				return fmt.Errorf("unable to write known exploited vulnerability to store: %w", err)
			}
		case grypeDB.EpssHandle:
			if err := w.store.AddEpss(&row); err != nil {
				return fmt.Errorf("unable to write EPSS to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

// fillInMissingSeverity will add a severity entry to the vulnerability record if it is missing, empty, or "unknown".
// The upstream NVD record is used to fill in these missing values. Note that the NVD provider is always guaranteed
// to be processed first before other providers.
func (w *writer) fillInMissingSeverity(handle *grypeDB.VulnerabilityHandle) {
	if handle == nil {
		return
	}

	blob := handle.BlobValue
	if blob == nil {
		return
	}

	id := strings.ToLower(blob.ID)
	isCVE := strings.HasPrefix(id, "cve-")
	if strings.ToLower(handle.ProviderID) == "nvd" && isCVE {
		if len(blob.Severities) > 0 {
			w.severityCache[id] = blob.Severities[0]
		}
		return
	}

	if !isCVE {
		return
	}

	// parse all string severities and remove all unknown values
	sevs := filterUnknownSeverities(blob.Severities)

	topSevStr := "none"
	if len(sevs) > 0 {
		switch v := sevs[0].Value.(type) {
		case string:
			topSevStr = v
		case fmt.Stringer:
			topSevStr = v.String()
		default:
			topSevStr = fmt.Sprintf("%v", sevs[0].Value)
		}
	}

	if len(sevs) > 0 {
		return // already has a severity, don't normalize
	}

	// add the top NVD severity value
	nvdSev, ok := w.severityCache[id]
	if !ok {
		log.WithFields("id", blob.ID).Trace("unable to find NVD severity")
		return
	}

	log.WithFields("id", blob.ID, "provider", handle.Provider, "sev-from", topSevStr, "sev-to", nvdSev).Trace("overriding irrelevant severity with data from NVD record")
	sevs = append([]grypeDB.Severity{nvdSev}, sevs...)
	handle.BlobValue.Severities = sevs
}

func filterUnknownSeverities(sevs []grypeDB.Severity) []grypeDB.Severity {
	var out []grypeDB.Severity
	for _, s := range sevs {
		if isKnownSeverity(s) {
			out = append(out, s)
		}
	}
	return out
}

func isKnownSeverity(s grypeDB.Severity) bool {
	switch v := s.Value.(type) {
	case string:
		return v != "" && strings.ToLower(v) != "unknown"
	default:
		return v != nil
	}
}

func (w writer) Close() error {
	// Finalize AlmaLinux aliases based on presence of AlmaLinux vulnerabilities
	if err := w.finalizeAliases(); err != nil {
		// Log error but don't fail the build process
		log.WithFields("error", err).Warn("failed to finalize AlmaLinux aliases")
	}

	if err := w.store.Close(); err != nil {
		return fmt.Errorf("unable to close store: %w", err)
	}

	log.WithFields("path", w.dbPath).Info("database created")

	return nil
}

// finalizeAliases conditionally removes RHEL aliases for AlmaLinux if AlmaLinux-specific vulnerabilities are present
func (w *writer) finalizeAliases() error {
	hasAlma, err := w.hasAlmaLinuxProvider()
	if err != nil {
		return fmt.Errorf("failed to check for AlmaLinux providers: %w", err)
	}

	if hasAlma {
		log.Info("AlmaLinux-specific vulnerabilities detected, removing RHEL aliases for AlmaLinux")

		// Remove RHEL aliases for alma and almalinux
		if err := w.removeAlmaRHELAliases(); err != nil {
			return fmt.Errorf("failed to remove RHEL aliases: %w", err)
		}

		// Add the correct alma -> almalinux mapping
		if err := w.addAlmaLinuxAlias(); err != nil {
			return fmt.Errorf("failed to add AlmaLinux alias: %w", err)
		}

		log.Info("Successfully updated AlmaLinux aliases")
	} else {
		log.Info("No AlmaLinux-specific vulnerabilities found, keeping RHEL aliases")
	}

	return nil
}

// hasAlmaLinuxProvider checks if any providers with ID "almalinux" exist in the database
func (w *writer) hasAlmaLinuxProvider() (bool, error) {
	type lowLevelReader interface {
		GetDB() *gorm.DB
	}

	db := w.store.(lowLevelReader).GetDB()
	var count int64
	err := db.Model(&grypeDB.Provider{}).
		Where("id = ?", "almalinux").
		Count(&count).Error
	return count > 0, err
}

// removeAlmaRHELAliases removes the default RHEL aliases for alma and almalinux
func (w *writer) removeAlmaRHELAliases() error {
	type lowLevelReader interface {
		GetDB() *gorm.DB
	}

	db := w.store.(lowLevelReader).GetDB()
	return db.Where("alias IN (?, ?) AND replacement = ?", "alma", "almalinux", "rhel").
		Delete(&grypeDB.OperatingSystemSpecifierOverride{}).Error
}

// addAlmaLinuxAlias adds the alma -> almalinux alias
func (w *writer) addAlmaLinuxAlias() error {
	type lowLevelReader interface {
		GetDB() *gorm.DB
	}

	db := w.store.(lowLevelReader).GetDB()
	alias := &grypeDB.OperatingSystemSpecifierOverride{
		Alias:           "alma",
		ReplacementName: stringPtr("almalinux"),
	}
	return db.Create(alias).Error
}

// stringPtr returns a pointer to the given string
func stringPtr(s string) *string {
	return &s
}
