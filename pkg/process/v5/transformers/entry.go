package transformers

import (
	"github.com/anchore/grype-db/pkg/data"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/purlvulnerability"
)

func NewEntries(vs []grypeDB.Vulnerability, purlVulns purlvulnerability.Vulnerabilities, metadata grypeDB.VulnerabilityMetadata) []data.Entry {
	// TODO: WILL: something to link the namespaces besides `nvd:cpe` back to the
	// same metadata record? Or just different ones for now?
	entries := []data.Entry{
		{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            metadata,
		},
	}
	for _, vuln := range vs {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		})
	}
	for _, vuln := range purlVulns.Generic {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		})
	}
	for _, vuln := range purlVulns.Maven {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		})
	}
	// TODO: DATA OVERRIDES: additional types of vulnerability
	return entries
}

func NewEntriesFromPURLVulnerabilities(purlVulns purlvulnerability.Vulnerabilities, metadata grypeDB.VulnerabilityMetadata) []data.Entry {
	entries := []data.Entry{
		{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            metadata,
		},
	}
	for _, vuln := range purlVulns.Generic {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		})
	}
	for _, vuln := range purlVulns.Maven {
		entries = append(entries, data.Entry{
			DBSchemaVersion: grypeDB.SchemaVersion,
			Data:            vuln,
		})
	}

	return entries
}
