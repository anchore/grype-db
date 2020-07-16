package curation

import (
	"path"
	"strings"
)

const (
	// Note: these names affect the *.json db metadata file names, don't change unless you need to
	UnknownDbType               = "unknown-db-type"
	VulnerabilityDbType         = "vulnerability"
	VulnerabilityMetadataDbType = "vulnerability-metadata"
)

type DatabaseType string

func ParseDatabaseTypeFromArchivePath(p string) DatabaseType {
	basename := path.Base(p)
	switch {
	case strings.HasPrefix(basename, VulnerabilityDbType):
		return VulnerabilityDbType
	case strings.HasPrefix(basename, VulnerabilityMetadataDbType):
		return VulnerabilityMetadataDbType
	}
	return UnknownDbType
}