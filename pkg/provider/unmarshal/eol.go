package unmarshal

import "io"

// EOLRecord represents a single end-of-life record from vunnel with its envelope.
type EOLRecord struct {
	Schema     string  `json:"schema"`
	Identifier string  `json:"identifier"` // e.g., "debian:13", "ubuntu:22.04"
	Item       EOLItem `json:"item"`
}

// EOLItem contains the end-of-life information for a product release.
// This data comes from endoflife.date and includes information about
// software/OS lifecycle status.
type EOLItem struct {
	Cycle        string          `json:"cycle"`
	Codename     *string         `json:"codename"`
	Label        string          `json:"label"`
	ReleaseDate  *string         `json:"release_date"`
	IsLTS        bool            `json:"is_lts"`
	LTSFrom      *string         `json:"lts_from"`
	IsEOAS       bool            `json:"is_eoas"`
	EOASFrom     *string         `json:"eoas_from"`
	IsEOL        bool            `json:"is_eol"`
	EOLFrom      *string         `json:"eol_from"`
	IsMaintained bool            `json:"is_maintained"`
	Identifiers  []EOLIdentifier `json:"identifiers"`
}

// EOLIdentifier represents a CPE or PURL identifier for an EOL entry.
type EOLIdentifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// IsEmpty returns true if the record has no meaningful data.
func (e EOLRecord) IsEmpty() bool {
	return e.Identifier == ""
}

// ProductName extracts the product name from the identifier (e.g., "debian" from "debian:13").
func (e EOLRecord) ProductName() string {
	for i, c := range e.Identifier {
		if c == ':' {
			return e.Identifier[:i]
		}
	}
	return e.Identifier
}

// EOLRecordEntries unmarshals EOL records from a reader.
func EOLRecordEntries(reader io.Reader) ([]EOLRecord, error) {
	return unmarshalSingleOrMulti[EOLRecord](reader)
}
