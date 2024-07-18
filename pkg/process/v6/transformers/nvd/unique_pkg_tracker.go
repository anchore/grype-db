package nvd

import (
	"github.com/anchore/grype-db/internal"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"sort"
	"strings"

	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
)

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

type ApplicationMatches []nvd.CpeMatch

func (a ApplicationMatches) CPEs() []string {
	cpes := internal.NewStringSet()
	for _, m := range a {
		// we dont need version info
		// TODO: what about update?
		atts, err := cpe.NewAttributes(strings.ToLower(m.Criteria))
		if err != nil {
			log.WithFields("cpe", m.Criteria, "error", err).Warn("could not parse CPE, dropping...")
			continue
		}
		atts.Version = cpe.Any
		cpes.Add(atts.String()) // TODO: this was normalized by the namespace... now this is ad-hoc... this seems bad
	}
	cpeList := cpes.ToSlice()
	sort.Strings(cpeList)
	return cpeList
}

func (s uniquePkgTracker) ApplicationMatches(i pkgCandidate) ApplicationMatches {
	return s[i].matches
}

type PlatformMatches []nvd.CpeMatch

func (a PlatformMatches) CPEs() []string {
	cpes := internal.NewStringSet()
	for _, m := range a {
		cpes.Add(strings.ToLower(m.Criteria)) // TODO: this was normalized by the namespace... now this is ad-hoc... this seems bad
	}
	if len(cpes) == 0 {
		return nil
	}
	cpeList := cpes.ToSlice()
	sort.Strings(cpeList)
	return cpeList
}

func (s uniquePkgTracker) PlatformMatches(i pkgCandidate) PlatformMatches {
	return s[i].platformMatches
}

func (s uniquePkgTracker) Add(i pkgCandidate, match nvd.CpeMatch) {
	m := s[i]
	if isPlatformMatch(match) {
		m.platformMatches = append(s[i].platformMatches, match)
	} else {
		m.matches = append(s[i].matches, match)
	}
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

func (s uniquePkgTracker) All() []pkgCandidate {
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
