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
		second := a[j].(grypeDB.UnaffectedPackageHandle)
		if first.Package.Name == second.Package.Name {
			if first.Package.Ecosystem == second.Package.Ecosystem {
				for _, b := range first.BlobValue.Ranges {
					for _, c := range second.BlobValue.Ranges {
						if b.Version.Constraint != c.Version.Constraint {
							return b.Version.Constraint < c.Version.Constraint
						}
					}
				}
			}
			return first.Package.Ecosystem < second.Package.Ecosystem
		}
		return first.Package.Name < second.Package.Name
	case grypeDB.AffectedPackageHandle:
		second := a[j].(grypeDB.AffectedPackageHandle)
		if first.Package.Name == second.Package.Name {
			if first.Package.Ecosystem == second.Package.Ecosystem {
				for _, b := range first.BlobValue.Ranges {
					for _, c := range second.BlobValue.Ranges {
						if b.Version.Constraint != c.Version.Constraint {
							return b.Version.Constraint < c.Version.Constraint
						}
					}
				}
			}
			return first.Package.Ecosystem < second.Package.Ecosystem
		}
	}
	return false
}
