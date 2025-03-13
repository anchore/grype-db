package nvd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
)

func TestUniquePkgTracker(t *testing.T) {

	t.Run("AddWithDetection and AllCandidates", func(t *testing.T) {
		tracker := newUniquePkgTracker()
		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		match := nvd.CpeMatch{Criteria: "cpe:2.3:o:vendor1:product1:1.0:*:*:*:*:*:*:*"}

		tracker.AddWithDetection(pkg1, match)

		require.Len(t, tracker.AllCandidates(), 1)
		assert.Equal(t, pkg1, tracker.AllCandidates()[0])
	})

	t.Run("AddExplicit", func(t *testing.T) {
		tracker := newUniquePkgTracker()
		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		appMatch := nvd.CpeMatch{Criteria: "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*"}
		platformMatch := nvd.CpeMatch{Criteria: "cpe:2.3:o:vendor1:platform:2.0:*:*:*:*:*:*:*"}

		tracker.AddExplicit(pkg1, appMatch, []nvd.CpeMatch{platformMatch})

		require.Len(t, tracker.AllCandidates(), 1)
		assert.Equal(t, pkg1, tracker.AllCandidates()[0])

		appMatches := tracker.ApplicationMatches(pkg1)
		require.Len(t, appMatches, 1)
		assert.Equal(t, appMatch.Criteria, appMatches[0].Criteria)

		platformMatches := tracker.PlatformMatches(pkg1)
		require.Len(t, platformMatches, 1)
		assert.Equal(t, platformMatch.Criteria, platformMatches[0].Criteria)
	})

	t.Run("Remove", func(t *testing.T) {
		tracker := newUniquePkgTracker()
		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		match := nvd.CpeMatch{Criteria: "cpe:2.3:o:vendor1:product1:1.0:*:*:*:*:*:*:*"}

		tracker.AddWithDetection(pkg1, match)
		tracker.Remove(pkg1)

		assert.Empty(t, tracker.AllCandidates())
	})

	t.Run("Contains", func(t *testing.T) {
		tracker := newUniquePkgTracker()
		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		match := nvd.CpeMatch{Criteria: "cpe:2.3:o:vendor1:product1:1.0:*:*:*:*:*:*:*"}

		assert.False(t, tracker.Contains(pkg1))

		tracker.AddWithDetection(pkg1, match)
		assert.True(t, tracker.Contains(pkg1))
	})

	t.Run("Diff", func(t *testing.T) {
		tracker1 := newUniquePkgTracker()
		tracker2 := newUniquePkgTracker()

		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		pkg2 := pkgCandidate{
			Product:        "product2",
			Vendor:         "vendor2",
			TargetSoftware: "software2",
		}
		pkg3 := pkgCandidate{
			Product:        "product3",
			Vendor:         "vendor3",
			TargetSoftware: "software3",
		}

		match := nvd.CpeMatch{Criteria: "cpe:2.3:o:vendor1:product1:1.0:*:*:*:*:*:*:*"}
		tracker1.AddWithDetection(pkg1, match)
		tracker1.AddWithDetection(pkg2, match)

		tracker2.AddWithDetection(pkg2, match)
		tracker2.AddWithDetection(pkg3, match)

		missing, extra := tracker1.Diff(tracker2)

		require.Len(t, missing, 1)
		assert.Equal(t, pkg1, missing[0])

		require.Len(t, extra, 1)
		assert.Equal(t, pkg3, extra[0])
	})

	t.Run("platformMatches", func(t *testing.T) {
		tracker := newUniquePkgTracker()
		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		platformMatch := nvd.CpeMatch{Criteria: "cpe:2.3:o:vendor1:platform:2.0:*:*:*:*:*:*:*"}

		tracker.AddWithDetection(pkg1, platformMatch)

		platformMatches := tracker.PlatformMatches(pkg1)
		require.Len(t, platformMatches, 1)
		assert.Equal(t, platformMatch.Criteria, platformMatches[0].Criteria)
	})

	t.Run("applicationMatches", func(t *testing.T) {
		tracker := newUniquePkgTracker()
		pkg1 := pkgCandidate{
			Product:        "product1",
			Vendor:         "vendor1",
			TargetSoftware: "software1",
		}
		appMatch := nvd.CpeMatch{Criteria: "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*"}

		tracker.AddWithDetection(pkg1, appMatch)

		appMatches := tracker.ApplicationMatches(pkg1)
		require.Len(t, appMatches, 1)
		assert.Equal(t, appMatch.Criteria, appMatches[0].Criteria)
	})
}
