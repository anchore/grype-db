package application

import (
	"fmt"
	"runtime"
	"runtime/debug"

	grypeDB "github.com/anchore/grype/grype/db"
)

const valueNotProvided = "[not provided]"

var version = valueNotProvided
var gitCommit = valueNotProvided
var gitDescription = valueNotProvided
var buildDate = valueNotProvided
var platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

type BuildInfo struct {
	Version        string `json:"version"`        // application semantic version
	GitCommit      string `json:"gitCommit"`      // git SHA at build-time
	GitDescription string `json:"gitDescription"` // indication of git tree (either "clean" or "dirty") at build-time
	BuildDate      string `json:"buildDate"`      // date of the build
	GoVersion      string `json:"goVersion"`      // go runtime version at build-time
	Compiler       string `json:"compiler"`       // compiler used at build-time
	Platform       string `json:"platform"`       // GOOS and GOARCH at build-time
	DBSchema       int    `json:"dbSchema"`
}

func ReadBuildInfo() BuildInfo {
	var buildRevision string
	var vcsModified bool
	var foundVcsModified bool
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				buildRevision = s.Value
			} else if s.Key == "vcs.modified" {
				vcsModified = s.Value == "true"
				foundVcsModified = true
			}
		}
	}

	if version == valueNotProvided {
		if buildRevision != "" {
			version = fmt.Sprintf("%s-adhoc-build", buildRevision)
		} else {
			version = fmt.Sprintf("%s (adhoc-build)", valueNotProvided)
		}
	}

	if gitCommit == valueNotProvided && buildRevision != "" {
		gitCommit = buildRevision
	}

	if gitDescription == valueNotProvided && foundVcsModified {
		if vcsModified {
			gitDescription = "dirty"
		} else {
			gitDescription = "clean"
		}
	}

	return BuildInfo{
		Version:        version,
		GitCommit:      gitCommit,
		GitDescription: gitDescription,
		BuildDate:      buildDate,
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
		Platform:       platform,
		DBSchema:       grypeDB.SchemaVersion,
	}
}
