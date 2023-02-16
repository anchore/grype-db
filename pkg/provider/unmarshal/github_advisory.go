package unmarshal

import (
	"io"
)

type GitHubAdvisory struct {
	Advisory struct {
		CVE     []string `json:"CVE"`
		FixedIn []struct {
			Ecosystem  string `json:"ecosystem"`
			Identifier string `json:"identifier"`
			Name       string `json:"name"`
			Namespace  string `json:"namespace"`
			Range      string `json:"range"`
		} `json:"FixedIn"`
		Metadata struct {
			CVE []string `json:"CVE"`
		} `json:"Metadata"`
		Severity  string      `json:"Severity"`
		Summary   string      `json:"Summary"`
		GhsaID    string      `json:"ghsaId"`
		Namespace string      `json:"namespace"`
		URL       string      `json:"url"`
		Withdrawn interface{} `json:"withdrawn"`
	} `json:"Advisory"`
}

func (g GitHubAdvisory) IsEmpty() bool {
	return g.Advisory.GhsaID == ""
}

func GitHubAdvisoryEntries(reader io.Reader) ([]GitHubAdvisory, error) {
	return unmarshalSingleOrMulti[GitHubAdvisory](reader)
}
