package internal

import grypeDB "github.com/anchore/grype/grype/db/v6"

type ByAffectedPackage []grypeDB.AffectedPackageHandle

func (a ByAffectedPackage) Len() int      { return len(a) }
func (a ByAffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByAffectedPackage) Less(i, j int) bool {
	if a[i].Package.Name == a[j].Package.Name {
		if a[i].Package.Ecosystem == a[j].Package.Ecosystem {
			for _, b := range a[i].BlobValue.Ranges {
				for _, c := range a[j].BlobValue.Ranges {
					if b.Version.Constraint != c.Version.Constraint {
						return b.Version.Constraint < c.Version.Constraint
					}
				}
			}
		}
		return a[i].Package.Ecosystem < a[j].Package.Ecosystem
	}
	return a[i].Package.Name < a[j].Package.Name
}

// TODO this should be cleaned up and deduplicated

type ByUnaffectedPackage []grypeDB.UnaffectedPackageHandle

func (a ByUnaffectedPackage) Len() int      { return len(a) }
func (a ByUnaffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByUnaffectedPackage) Less(i, j int) bool {
	if a[i].Package.Name == a[j].Package.Name {
		if a[i].Package.Ecosystem == a[j].Package.Ecosystem {
			for _, b := range a[i].BlobValue.Ranges {
				for _, c := range a[j].BlobValue.Ranges {
					if b.Version.Constraint != c.Version.Constraint {
						return b.Version.Constraint < c.Version.Constraint
					}
				}
			}
		}
		return a[i].Package.Ecosystem < a[j].Package.Ecosystem
	}
	return a[i].Package.Name < a[j].Package.Name
}

type ByAny []any

func (a ByAny) Len() int      { return len(a) }
func (a ByAny) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByAny) Less(i, j int) bool {
	switch first := a[i].(type) {
	case grypeDB.UnaffectedPackageHandle:
		if second, ok := a[j].(grypeDB.UnaffectedPackageHandle); ok {
			return comparePackageHandles(first.Package, first.BlobValue.Ranges, second.Package, second.BlobValue.Ranges)
		}
	case grypeDB.AffectedPackageHandle:
		if second, ok := a[j].(grypeDB.AffectedPackageHandle); ok {
			return comparePackageHandles(first.Package, first.BlobValue.Ranges, second.Package, second.BlobValue.Ranges)
		}
	}
	return false
}

// comparePackageHandles compares two package handles by name, ecosystem, then version constraints
func comparePackageHandles(pkg1 *grypeDB.Package, ranges1 []grypeDB.Range, pkg2 *grypeDB.Package, ranges2 []grypeDB.Range) bool {
	if pkg1.Name != pkg2.Name {
		return pkg1.Name < pkg2.Name
	}
	if pkg1.Ecosystem != pkg2.Ecosystem {
		return pkg1.Ecosystem < pkg2.Ecosystem
	}

	// compare version constraints
	for _, r1 := range ranges1 {
		for _, r2 := range ranges2 {
			if r1.Version.Constraint != r2.Version.Constraint {
				return r1.Version.Constraint < r2.Version.Constraint
			}
		}
	}
	return false
}
