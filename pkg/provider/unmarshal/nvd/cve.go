package nvd

import (
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/jinzhu/copier"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd/cvss20"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd/cvss30"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd/cvss31"
)

// note: this was autogenerated with some manual tweaking (see schema/nvd/cve-api-json/README.md)

type Operator string

const (
	And Operator = "AND"
	Or  Operator = "OR"
)

const englishLanguage = "en"

// this is the struct to use when unmarshalling directly from the API (which grype-db is NOT doing)
// type APIResults struct {
//	Format          string          `json:"format"`
//	ResultsPerPage  int64           `json:"resultsPerPage"`
//	StartIndex      int64           `json:"startIndex"`
//	Timestamp       string          `json:"timestamp"`
//	TotalResults    int64           `json:"totalResults"`
//	Version         string          `json:"version"`
//	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
//}

type Vulnerability struct {
	Cve CveItem `json:"cve"`
}

type CveItem struct {
	ID string `json:"id"`
	// CisaActionDue         *string         `json:"cisaActionDue,omitempty"`
	// CisaExploitAdd        *string         `json:"cisaExploitAdd,omitempty"`
	// CisaRequiredAction    *string         `json:"cisaRequiredAction,omitempty"`
	// CisaVulnerabilityName *string         `json:"cisaVulnerabilityName,omitempty"`
	Configurations []Configuration `json:"configurations,omitempty"`
	Descriptions   []LangString    `json:"descriptions"`
	// EvaluatorComment      *string         `json:"evaluatorComment,omitempty"`
	// EvaluatorImpact       *string         `json:"evaluatorImpact,omitempty"`
	// EvaluatorSolution     *string         `json:"evaluatorSolution,omitempty"`
	LastModified     string      `json:"lastModified"`
	Metrics          *Metrics    `json:"metrics,omitempty"`
	Published        string      `json:"published"`
	References       []Reference `json:"references"`
	SourceIdentifier *string     `json:"sourceIdentifier,omitempty"`
	// VendorComments        []VendorComment `json:"vendorComments,omitempty"`
	VulnStatus *string `json:"vulnStatus,omitempty"`
	// Weaknesses            []Weakness      `json:"weaknesses,omitempty"`
}

type Configuration struct {
	Negate   *bool     `json:"negate,omitempty"`
	Nodes    []Node    `json:"nodes"`
	Operator *Operator `json:"operator,omitempty"`
}

type Node struct {
	CpeMatch []CpeMatch `json:"cpeMatch"`
	Negate   *bool      `json:"negate,omitempty"`
	Operator Operator   `json:"operator"`
}

type CpeMatch struct {
	Criteria              string  `json:"criteria"`
	MatchCriteriaID       string  `json:"matchCriteriaId"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	Vulnerable            bool    `json:"vulnerable"`
}

type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics scores for a vulnerability as found on NVD.
type Metrics struct {
	CvssMetricV2  []CvssV2  `json:"cvssMetricV2,omitempty"`  // CVSS V2.0 score.
	CvssMetricV30 []CvssV30 `json:"cvssMetricV30,omitempty"` // CVSS V3.0 score.
	CvssMetricV31 []CvssV31 `json:"cvssMetricV31,omitempty"` // CVSS V3.1 score.
}

type CvssV2 struct {
	// ACInsufInfo             *bool         `json:"acInsufInfo,omitempty"`
	BaseSeverity        *string       `json:"baseSeverity,omitempty"`
	CvssData            cvss20.Cvss20 `json:"cvssData"`
	ExploitabilityScore *float64      `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64      `json:"impactScore,omitempty"`
	// ObtainAllPrivilege      *bool         `json:"obtainAllPrivilege,omitempty"`
	// ObtainOtherPrivilege    *bool         `json:"obtainOtherPrivilege,omitempty"`
	// ObtainUserPrivilege     *bool         `json:"obtainUserPrivilege,omitempty"`
	Source string   `json:"source"`
	Type   CvssType `json:"type"`
	// UserInteractionRequired *bool         `json:"userInteractionRequired,omitempty"`
}

type CvssV30 struct {
	CvssData            cvss30.Cvss30 `json:"cvssData"`
	ExploitabilityScore *float64      `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64      `json:"impactScore,omitempty"`
	Source              string        `json:"source"`
	Type                CvssType      `json:"type"`
}

type CvssV31 struct {
	CvssData            cvss31.Cvss31 `json:"cvssData"`
	ExploitabilityScore *float64      `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64      `json:"impactScore,omitempty"`
	Source              string        `json:"source"`
	Type                CvssType      `json:"type"`
}

// CvssType relative to the NVD docs: "type identifies whether the organization is a primary or secondary source.
// Primary sources include the NVD and CNA who have reached the provider level in CVMAP. 10% of provider level
// submissions are audited by the NVD. If a submission has been audited the NVD will appear as the primary source
// and the provider level CNA will appear as the secondary source."
type CvssType string

const (
	Primary   CvssType = "Primary"
	Secondary CvssType = "Secondary"
)

type Reference struct {
	Source *string  `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url"`
}

// type VendorComment struct {
//	Comment      string `json:"comment"`
//	LastModified string `json:"lastModified"`
//	Organization string `json:"organization"`
//}
//
// type Weakness struct {
//	Description []LangString `json:"description"`
//	Source      string       `json:"source"`
//	Type        string       `json:"type"`
//}

func (o CveItem) Description() string {
	for _, d := range o.Descriptions {
		if d.Lang == englishLanguage {
			return d.Value
		}
	}
	return ""
}

type CvssSummary struct {
	Source              string
	Type                CvssType
	Version             string
	Vector              string
	BaseScore           float64
	ExploitabilityScore *float64
	ImpactScore         *float64
	baseSeverity        *string
}

func (o CvssSummary) Severity() string {
	if o.baseSeverity != nil {
		return cases.Title(language.English).String(*o.baseSeverity)
	}
	return ""
}

func (o CvssSummary) version() *semver.Version {
	v, err := semver.NewVersion(o.Version)
	if err != nil {
		return semver.MustParse("2.0")
	}
	return v
}

type CvssSummaries []CvssSummary

func (o CvssSummaries) Len() int {
	return len(o)
}

func (o CvssSummaries) Less(i, j int) bool {
	iEntry := o[i]
	jEntry := o[j]
	iV := iEntry.version()
	jV := jEntry.version()
	if iV == jV {
		if iEntry.Type == Primary && jEntry.Type == Secondary {
			return false
		} else if iEntry.Type == Secondary && jEntry.Type == Primary {
			return true
		}
		return false
	}
	return iV.LessThan(jV)
}

func (o CvssSummaries) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

func (o CvssSummaries) Severity() string {
	for _, c := range o {
		sev := c.Severity()
		if sev != "" {
			return sev
		}
	}
	return ""
}

func (o CvssSummaries) Sorted() CvssSummaries {
	var n CvssSummaries
	if err := copier.Copy(&n, &o); err != nil {
		panic(err)
	}
	sort.Sort(sort.Reverse(n))
	return n
}

func (o CveItem) CVSS() []CvssSummary {
	if o.Metrics == nil {
		return nil
	}

	var results CvssSummaries

	for _, c := range o.Metrics.CvssMetricV2 {
		results = append(results,
			CvssSummary{
				Source:              c.Source,
				Type:                c.Type,
				Version:             c.CvssData.Version,
				Vector:              c.CvssData.VectorString,
				BaseScore:           c.CvssData.BaseScore,
				ExploitabilityScore: c.ExploitabilityScore,
				ImpactScore:         c.ImpactScore,
				baseSeverity:        c.BaseSeverity,
			},
		)
	}
	for _, c := range o.Metrics.CvssMetricV30 {
		sev := string(c.CvssData.BaseSeverity)
		results = append(results,
			CvssSummary{
				Source:              c.Source,
				Type:                c.Type,
				Version:             c.CvssData.Version,
				Vector:              c.CvssData.VectorString,
				BaseScore:           c.CvssData.BaseScore,
				ExploitabilityScore: c.ExploitabilityScore,
				ImpactScore:         c.ImpactScore,
				baseSeverity:        &sev,
			},
		)
	}
	for _, c := range o.Metrics.CvssMetricV31 {
		sev := string(c.CvssData.BaseSeverity)
		results = append(results,
			CvssSummary{
				Source:              c.Source,
				Type:                c.Type,
				Version:             c.CvssData.Version,
				Vector:              c.CvssData.VectorString,
				BaseScore:           c.CvssData.BaseScore,
				ExploitabilityScore: c.ExploitabilityScore,
				ImpactScore:         c.ImpactScore,
				baseSeverity:        &sev,
			},
		)
	}

	return results
}

func (o Vulnerability) IsEmpty() bool {
	return o.Cve.ID == ""
}
