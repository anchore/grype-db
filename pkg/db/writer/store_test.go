package writer

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype-db/pkg/db/model"
	"github.com/anchore/grype-db/pkg/db/reader"
	"github.com/go-test/deep"
)

func assertIDReader(t *testing.T, reader db.IDReader, expected db.ID) {
	t.Helper()
	if actual, err := reader.GetID(); err != nil {
		t.Fatalf("failed to get ID: %+v", err)
	} else {
		diffs := deep.Equal(&expected, actual)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("Diff: %+v", d)
			}
		}
	}
}

func TestStore_GetID_SetID(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	expected := db.ID{
		BuildTimestamp: time.Now().UTC(),
		SchemaVersion:  2,
	}

	if err = store.SetID(expected); err != nil {
		t.Fatalf("failed to set ID: %+v", err)
	}

	assertIDReader(t, store, expected)

	// gut check on reader
	storeReader, othercleanfn, err := reader.NewStore(dbTempFile.Name())
	defer othercleanfn()
	if err != nil {
		t.Fatalf("could not open db reader: %+v", err)
	}
	assertIDReader(t, storeReader, expected)

}

func assertVulnerabilityReader(t *testing.T, reader db.VulnerabilityStoreReader, namespace, name string, expected []*db.Vulnerability) {
	if actual, err := reader.GetVulnerability(namespace, name); err != nil {
		t.Fatalf("failed to get Vulnerability: %+v", err)
	} else {
		if len(actual) != len(expected) {
			t.Fatalf("unexpected number of vulns: %d", len(actual))
		}

		for idx := range actual {
			diffs := deep.Equal(expected[idx], &actual[idx])
			if len(diffs) > 0 {
				for _, d := range diffs {
					t.Errorf("Diff: %+v", d)
				}
			}
		}
	}
}

func TestStore_GetVulnerability_SetVulnerability(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	extra := []*db.Vulnerability{
		{
			ID:                   "my-cve-33333",
			RecordSource:         "record-source",
			PackageName:          "package-name-2",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 1.0",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
			FixedInVersion:       "2.0.1",
		},
		{
			ID:                   "my-other-cve-33333",
			RecordSource:         "record-source",
			PackageName:          "package-name-3",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 509.2.2",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
		},
	}

	expected := []*db.Vulnerability{
		{
			ID:                   "my-cve",
			RecordSource:         "record-source",
			PackageName:          "package-name",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 1.0",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
			FixedInVersion:       "1.0.1",
		},
		{
			ID:                   "my-other-cve",
			RecordSource:         "record-source",
			PackageName:          "package-name",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 509.2.2",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
			FixedInVersion:       "4.0.5",
		},
	}

	total := append(expected, extra...)

	// case: ignore nil entries
	if err = store.AddVulnerability(nil, nil, nil, nil); err != nil {
		t.Fatalf("failed to set Vulnerability: %+v", err)
	}

	if err = store.AddVulnerability(total...); err != nil {
		t.Fatalf("failed to set Vulnerability: %+v", err)
	}

	var allEntries []model.VulnerabilityModel
	store.vulnDb.Find(&allEntries)
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	assertVulnerabilityReader(t, store, expected[0].Namespace, expected[0].PackageName, expected)

	// gut check on reader
	storeReader, othercleanfn, err := reader.NewStore(dbTempFile.Name())
	defer othercleanfn()
	if err != nil {
		t.Fatalf("could not open db reader: %+v", err)
	}
	assertVulnerabilityReader(t, storeReader, expected[0].Namespace, expected[0].PackageName, expected)

}

func assertVulnerabilityMetadataReader(t *testing.T, reader db.VulnerabilityMetadataStoreReader, id, recordSource string, expected *db.VulnerabilityMetadata) {
	if actual, err := reader.GetVulnerabilityMetadata(id, recordSource); err != nil {
		t.Fatalf("failed to get metadata: %+v", err)
	} else {

		diffs := deep.Equal(expected, actual)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("Diff: %+v", d)
			}
		}
	}

}

func TestStore_GetVulnerabilityMetadata_SetVulnerabilityMetadata(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	total := []*db.VulnerabilityMetadata{
		{
			ID:           "my-cve",
			RecordSource: "record-source",
			Severity:     "pretty bad",
			Links:        []string{"https://ancho.re"},
			Description:  "best description ever",
			CvssV2: &db.Cvss{
				BaseScore:           1.1,
				ExploitabilityScore: 2.2,
				ImpactScore:         3.3,
				Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--NOT",
			},
			CvssV3: &db.Cvss{
				BaseScore:           1.3,
				ExploitabilityScore: 2.1,
				ImpactScore:         3.2,
				Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--NICE",
			},
		},
		{
			ID:           "my-other-cve",
			RecordSource: "record-source",
			Severity:     "pretty bad",
			Links:        []string{"https://ancho.re"},
			Description:  "worst description ever",
			CvssV2: &db.Cvss{
				BaseScore:           4.1,
				ExploitabilityScore: 5.2,
				ImpactScore:         6.3,
				Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
			},
			CvssV3: &db.Cvss{
				BaseScore:           1.4,
				ExploitabilityScore: 2.5,
				ImpactScore:         3.6,
				Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
			},
		},
	}

	// case: ignore nil entries
	if err = store.AddVulnerabilityMetadata(nil, nil, nil, nil); err != nil {
		t.Fatalf("failed to set metadata: %+v", err)
	}

	if err = store.AddVulnerabilityMetadata(total...); err != nil {
		t.Fatalf("failed to set metadata: %+v", err)
	}

	var allEntries []model.VulnerabilityMetadataModel
	store.vulnDb.Find(&allEntries)
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	// gut check on reader
	storeReader, othercleanfn, err := reader.NewStore(dbTempFile.Name())
	defer othercleanfn()
	if err != nil {
		t.Fatalf("could not open db reader: %+v", err)
	}

	assertVulnerabilityMetadataReader(t, storeReader, total[0].ID, total[0].RecordSource, total[0])

}

func TestStore_MergeVulnerabilityMetadata(t *testing.T) {
	tests := []struct {
		name     string
		add      []db.VulnerabilityMetadata
		expected db.VulnerabilityMetadata
		err      bool
	}{
		{
			name: "go-case",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 2.5,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "worst description ever",
				CvssV2: &db.Cvss{
					BaseScore:           4.1,
					ExploitabilityScore: 5.2,
					ImpactScore:         6.3,
					Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
				},
				CvssV3: &db.Cvss{
					BaseScore:           1.4,
					ExploitabilityScore: 2.5,
					ImpactScore:         3.6,
					Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
				},
			},
		},
		{
			name: "merge-links",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://google.com"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://yahoo.com"},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re", "https://google.com", "https://yahoo.com"},
			},
		},
		{
			name: "bad-severity",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "meh, push that for next tuesday...",
					Links:        []string{"https://redhat.com"},
				},
			},
			err: true,
		},
		{
			name: "mismatch-description",
			err:  true,
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 2.5,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 2.5,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
		{
			name: "mismatch-cvss2",
			err:  true,
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 2.5,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 2.5,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
		{
			name: "mismatch-cvss3",
			err:  true,
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 2.5,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					CvssV2: &db.Cvss{
						BaseScore:           4.1,
						ExploitabilityScore: 5.2,
						ImpactScore:         6.3,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					CvssV3: &db.Cvss{
						BaseScore:           1.4,
						ExploitabilityScore: 0,
						ImpactScore:         3.6,
						Vector:              "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbTempDir, err := ioutil.TempDir("", "grype-db-test-store")
			if err != nil {
				t.Fatalf("could not create temp file: %+v", err)
			}
			defer os.RemoveAll(dbTempDir)

			store, cleanupFn, err := NewStore(dbTempDir, true)
			defer cleanupFn()
			if err != nil {
				t.Fatalf("could not create store: %+v", err)
			}

			// add each metadata in order
			var theErr error
			for _, metadata := range test.add {
				err = store.AddVulnerabilityMetadata(&metadata)
				if err != nil {
					theErr = err
					break
				}
			}

			if test.err && theErr == nil {
				t.Fatalf("expected error but did not get one")
			} else if !test.err && theErr != nil {
				t.Fatalf("expected no error but got one: %+v", theErr)
			} else if test.err && theErr != nil {
				// test pass...
				return
			}

			// ensure there is exactly one entry
			var allEntries []model.VulnerabilityMetadataModel
			store.vulnDb.Find(&allEntries)
			if len(allEntries) != 1 {
				t.Fatalf("unexpected number of entries: %d", len(allEntries))
			}

			// get the resulting metadata object
			if actual, err := store.GetVulnerabilityMetadata(test.expected.ID, test.expected.RecordSource); err != nil {
				t.Fatalf("failed to get metadata: %+v", err)
			} else {
				diffs := deep.Equal(&test.expected, actual)
				if len(diffs) > 0 {
					for _, d := range diffs {
						t.Errorf("Diff: %+v", d)
					}
				}
			}
		})
	}
}
