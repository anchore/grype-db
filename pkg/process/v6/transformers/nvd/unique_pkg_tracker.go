package nvd

import (
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
	"github.com/anchore/syft/syft/cpe"
)

type applicationMatches []nvd.CpeMatch

type platformMatches []nvd.CpeMatch

type matches struct {
	platformMatches []nvd.CpeMatch
	matches         []nvd.CpeMatch
}

type uniquePkgTracker map[pkgCandidate]matches

func newUniquePkgTracker() uniquePkgTracker {
	return make(uniquePkgTracker)
}

func (s uniquePkgTracker) Diff(other uniquePkgTracker) (missing []pkgCandidate, extra []pkgCandidate) {
	for k := range s {
		if !other.Contains(k) {
			missing = append(missing, k)
		}
	}

	for k := range other {
		if !s.Contains(k) {
			extra = append(extra, k)
		}
	}

	return
}

func (a applicationMatches) CPEs() []string {
	cpes := strset.New()
	for _, m := range a {
		atts, err := cpe.NewAttributes(strings.ToLower(m.Criteria))
		if err != nil {
			log.WithFields("cpe", m.Criteria, "error", err).Warn("could not parse CPE, dropping...")
			continue
		}
		// we reason about version information later, so we can ignore it here
		atts.Version = cpe.Any
		atts.Update = cpe.Any
		cpes.Add(atts.String())
	}
	cpeList := cpes.List()
	sort.Strings(cpeList)
	return cpeList
}

func (s uniquePkgTracker) ApplicationMatches(i pkgCandidate) applicationMatches {
	return s[i].matches
}

func (a platformMatches) CPEs() []string {
	cpes := strset.New()
	for _, m := range a {
		cpes.Add(strings.ToLower(m.Criteria))
	}
	if cpes.Size() == 0 {
		return nil
	}
	cpeList := cpes.List()
	sort.Strings(cpeList)
	return cpeList
}

func (s uniquePkgTracker) PlatformMatches(i pkgCandidate) platformMatches {
	return s[i].platformMatches
}

func (s uniquePkgTracker) AddWithDetection(i pkgCandidate, matches ...nvd.CpeMatch) {
	m := s[i]
	for _, match := range matches {
		if isPlatformMatch(match) {
			m.platformMatches = append(m.platformMatches, match)
		} else {
			m.matches = append(m.matches, match)
		}
	}
	s[i] = m
}

func (s uniquePkgTracker) AddExplicit(i pkgCandidate, applicationMatches nvd.CpeMatch, platformMatches []nvd.CpeMatch) {
	m := s[i]
	m.platformMatches = append(m.platformMatches, platformMatches...)
	m.matches = append(m.matches, applicationMatches)
	s[i] = m
}

func isPlatformMatch(match nvd.CpeMatch) bool {
	fields := strings.Split(match.Criteria, ":")
	if len(fields) > 2 {
		return fields[2] == "o"
	}
	return false
}

func (s uniquePkgTracker) Remove(i pkgCandidate) {
	delete(s, i)
}

func (s uniquePkgTracker) Contains(i pkgCandidate) bool {
	_, ok := s[i]
	return ok
}

func (s uniquePkgTracker) AllCandidates() []pkgCandidate {
	res := make([]pkgCandidate, len(s))
	idx := 0
	for k := range s {
		res[idx] = k
		idx++
	}

	sort.SliceStable(res, func(i, j int) bool {
		return res[i].String() < res[j].String()
	})

	return res
}
