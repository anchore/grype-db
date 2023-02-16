package data

import "github.com/anchore/grype-db/pkg/provider/unmarshal"

// Transformers are functions that know how ta take individual data shapes defined in the unmarshal package and
// reshape the data into data.Entry objects that are writable by a data.Writer. Transformers are dependency-injected
// into commonly-shared data.Processors in the individual process.v* packages.

type GitHubTransformer func(entry unmarshal.GitHubAdvisory) ([]Entry, error)
type MSRCTransformer func(entry unmarshal.MSRCVulnerability) ([]Entry, error)
type NVDTransformer func(entry unmarshal.NVDVulnerability) ([]Entry, error)
type OSTransformer func(entry unmarshal.OSVulnerability) ([]Entry, error)
type MatchExclusionTransformer func(entry unmarshal.MatchExclusion) ([]Entry, error)
