package sqlite

import (
	"encoding/json"
	"time"

	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/pkg/db"
)

type idModel struct {
	BuildTimestamp time.Time
	SchemaVersion  string
}

type vulnerabilityModel struct {
	ID                   string `gorm:"primary_key; index:vulnerability_id_index"`
	RecordSource         string `gorm:"primary_key; index:vulnerability_id_index"`
	PackageName          string `gorm:"index:get_vulnerability_index"`
	Namespace            string `gorm:"index:get_vulnerability_index"`
	VersionConstraint    string
	VersionFormat        string
	CPEs                 string
	ProxyVulnerabilities string
}

type vulnerabilityMetadataModel struct {
	ID           string `gorm:"primary_key; index:vulnerability_metadata_id_index"`
	RecordSource string `gorm:"primary_key; index:vulnerability_metadata_id_index"`
	Severity     string
	Links        string
}

func newIDModel(id db.ID) idModel {
	return idModel{
		BuildTimestamp: id.BuildTimestamp,
		SchemaVersion:  id.SchemaVersion.String(),
	}
}

func newVulnerabilityModel(vulnerability db.Vulnerability) vulnerabilityModel {
	cpes, err := json.Marshal(vulnerability.CPEs)
	if err != nil {
		// TODO: just no
		panic(err)
	}

	proxy, err := json.Marshal(vulnerability.ProxyVulnerabilities)
	if err != nil {
		// TODO: just no
		panic(err)
	}

	return vulnerabilityModel{
		ID:                   vulnerability.ID,
		PackageName:          vulnerability.PackageName,
		RecordSource:         vulnerability.RecordSource,
		Namespace:            vulnerability.Namespace,
		VersionConstraint:    vulnerability.VersionConstraint,
		VersionFormat:        vulnerability.VersionFormat,
		CPEs:                 string(cpes),
		ProxyVulnerabilities: string(proxy),
	}
}

func newVulnerabilityMetadataModel(metadata db.VulnerabilityMetadata) vulnerabilityMetadataModel {
	links, err := json.Marshal(metadata.Links)
	if err != nil {
		// TODO: just no
		panic(err)
	}

	return vulnerabilityMetadataModel{
		ID:           metadata.ID,
		RecordSource: metadata.RecordSource,
		Severity:     metadata.Severity,
		Links:        string(links),
	}
}

func (m *idModel) Inflate() db.ID {
	return db.ID{
		BuildTimestamp: m.BuildTimestamp,
		SchemaVersion:  *version.Must(version.NewVersion(m.SchemaVersion)),
	}
}

func (m *vulnerabilityModel) Inflate() db.Vulnerability {
	var cpes []string
	err := json.Unmarshal([]byte(m.CPEs), &cpes)
	if err != nil {
		// TODO: just no
		panic(err)
	}

	var proxy []string
	err = json.Unmarshal([]byte(m.ProxyVulnerabilities), &proxy)
	if err != nil {
		// TODO: just no
		panic(err)
	}

	return db.Vulnerability{
		ID:                   m.ID,
		RecordSource:         m.RecordSource,
		PackageName:          m.PackageName,
		Namespace:            m.Namespace,
		VersionConstraint:    m.VersionConstraint,
		VersionFormat:        m.VersionFormat,
		CPEs:                 cpes,
		ProxyVulnerabilities: proxy,
	}
}

func (m *vulnerabilityMetadataModel) Inflate() db.VulnerabilityMetadata {
	var links []string
	err := json.Unmarshal([]byte(m.Links), &links)
	if err != nil {
		// TODO: just no
		panic(err)
	}

	return db.VulnerabilityMetadata{
		ID:           m.ID,
		RecordSource: m.RecordSource,
		Severity:     m.Severity,
		Links:        links,
	}
}
