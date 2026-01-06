package unmarshal

import "io"

// EOLRecord represents a single end-of-life record from vunnel.
// This parses the "item" content directly (not the full envelope).
type EOLRecord struct {
	Product      string          `json:"product"`
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
	return e.Product == ""
}

// ProductName returns the product name from the record.
func (e EOLRecord) ProductName() string {
	return e.Product
}

// EOLRecordEntries unmarshals EOL records from a reader.
func EOLRecordEntries(reader io.Reader) ([]EOLRecord, error) {
	return unmarshalSingleOrMulti[EOLRecord](reader)
}
