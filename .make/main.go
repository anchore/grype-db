package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	. "github.com/anchore/go-make" //nolint:revive,staticcheck // go-make is intended to be dot-imported so tasks read like a Makefile

	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/log"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

const (
	project    = "grype-db"
	snapshotBn = "snapshot" // goreleaser dist dir

	// dataImageName is the OCI repo holding per-provider vunnel data caches.
	dataImageName = "ghcr.io/anchore/" + project + "/data"
	// sourceRepoURL annotates pushed cache images with their source repo.
	sourceRepoURL = "https://github.com/anchore/" + project
	// grypeDB is the grype-db CLI invocation used by the data-management tasks,
	// pinned to the publishing config (mirrors the old Makefile $(GRYPE_DB)).
	grypeDB = "go run ./cmd/" + project + "/main.go -c config/" + project + "/publish-nightly-r2.yaml"
)

func main() {
	Makefile(
		// framework-provided tasks: lint, format, lint:fix, check-licenses,
		// static-analysis, unit, fixtures, snapshot(s), (ci:)release, changelog, etc.
		golint.Tasks(golint.SkipTests()),
		gotest.Tasks(
			gotest.CoverageThreshold(47),
			gotest.ExcludeGlob("**/test/**"),
		),
		goreleaser.Tasks(),

		// grype-db data-management tasks (vunnel provider caches in ghcr.io)
		showProvidersTask(),
		ciOrasGHCRLoginTask(),
		downloadProviderCacheTask(),
		refreshProviderCacheTask(),
		uploadProviderCacheTask(),
		downloadAllProviderCacheTask(),
		ciCheckTask(),

		// go + python test orchestration
		cliTasks(),
		dbAcceptanceTask(),

		// the ./manager python subproject (driven by its own Makefile)
		managerTasks(),

		// code generation
		generateProcessorCodeTask(),

		// cleanup
		cleanDBTask(),
		clearTestCacheTask(),
	)
}

// param resolves a `key=value` parameter passed on the make command line.
//
// go-make never sees these: `make <task> provider=foo` is parsed by GNU make as
// a command-line variable assignment, not a goal. GNU make does, however, export
// command-line variable assignments into each recipe's environment, so by the
// time `go run -C .make .` executes, `provider` is present in our environment.
// We also accept the same `key=value` form passed directly as a CLI arg (e.g.
// `go run -C .make . download-provider-cache provider=foo`).
func param(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	for _, arg := range os.Args[1:] {
		if k, v, ok := strings.Cut(arg, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// requireParam is param but fails the task when the parameter is missing.
func requireParam(key string) string {
	v := param(key)
	if v == "" {
		lang.Throw(fmt.Errorf("required parameter %q is not set (pass %s=<value>)", key, key))
	}
	return v
}

// cacheDate returns the `date=` parameter, or today's UTC date in the yy-mm-dd
// form used to tag provider cache images (mirrors the old Makefile `date` var).
func cacheDate() string {
	if d := param("date"); d != "" {
		return d
	}
	return time.Now().UTC().Format("06-01-02")
}

// orasFlags adds --no-tty in CI so oras doesn't emit terminal control sequences.
func orasFlags() string {
	if os.Getenv("CI") == "true" {
		return "--no-tty"
	}
	return ""
}

// showProvidersTask prints the JSON list of providers used to build the DB. CI
// captures this via `content=$(make show-providers)` to build a job matrix, so
// only the JSON may reach stdout: go-make logs go to stderr, the grype-db
// invocation is run quietly, and we print the captured output directly.
func showProvidersTask() Task {
	return Task{
		Name:        "show-providers",
		Description: "list the providers used to build the DB (JSON)",
		Run: func() {
			out := Run(grypeDB+" list-providers -q -o json", run.Quiet())
			fmt.Println(out)
		},
	}
}

// ciOrasGHCRLoginTask logs oras into ghcr.io using CI credentials. The token is
// passed on stdin (never as an argument) so it can't leak into process listings
// or logs.
func ciOrasGHCRLoginTask() Task {
	return Task{
		Name:        "ci-oras-ghcr-login",
		Description: "log into ghcr.io with oras using CI credentials",
		Run: func() {
			user := os.Getenv("GITHUB_USERNAME")
			token := os.Getenv("GITHUB_TOKEN")
			if user == "" {
				lang.Throw(fmt.Errorf("GITHUB_USERNAME environment variable is not set"))
			}
			if token == "" {
				lang.Throw(fmt.Errorf("GITHUB_TOKEN environment variable is not set"))
			}
			Run("oras login ghcr.io --username "+user+" --password-stdin", run.Stdin(strings.NewReader(token)))
		},
	}
}

// downloadProviderCacheTask pulls a provider's data cache image and restores it.
// oras preserves the archive's relative path (.cache/vunnel/<provider>/...), so
// `cache restore` reads it straight back. A missing image fails the task; CI
// callers wrap this in `|| true` to treat "no cache yet" as non-fatal.
func downloadProviderCacheTask() Task {
	return Task{
		Name:        "download-provider-cache",
		Description: "download and restore a provider's data cache (params: provider, date)",
		Run: func() {
			provider := requireParam("provider")
			date := cacheDate()
			Log("Downloading and restoring %q provider data cache (%s)", provider, date)
			lang.Throw(downloadProviderCache(provider, date))
		},
	}
}

// downloadProviderCache pulls and restores a single provider's cache, returning
// an error instead of panicking so callers (download-all) can retry. The Run
// helper panics on failure; we recover that into a normal error.
func downloadProviderCache(provider, date string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	ref := fmt.Sprintf("%s/%s:%s", dataImageName, provider, date)
	Run(fmt.Sprintf("oras pull %s %s", orasFlags(), ref))
	Run(fmt.Sprintf("%s cache restore --path .cache/vunnel/%s/grype-db-cache.tar.gz --delete-existing", grypeDB, provider))
	file.Delete(".cache/vunnel/" + provider)
	return nil
}

// refreshProviderCacheTask runs the provider to pull fresh upstream data.
func refreshProviderCacheTask() Task {
	return Task{
		Name:        "refresh-provider-cache",
		Description: "refresh a provider's data cache from upstream (param: provider)",
		Run: func() {
			provider := requireParam("provider")
			Log("Refreshing %q provider data cache", provider)
			Run(fmt.Sprintf("%s pull -v -p %s", grypeDB, provider))
		},
	}
}

// uploadProviderCacheTask backs up a provider's cache and pushes it to ghcr.io,
// tagging it both with the date and `latest`. CI-only (see ci-check).
func uploadProviderCacheTask() Task {
	return Task{
		Name:         "upload-provider-cache",
		Description:  "back up and upload a provider's data cache (params: provider, date)",
		Dependencies: Deps("ci-check"),
		Run: func() {
			provider := requireParam("provider")
			date := cacheDate()
			ref := fmt.Sprintf("%s/%s:%s", dataImageName, provider, date)
			dir := filepath.Join(".cache/vunnel", provider)
			archive := filepath.Join(dir, "grype-db-cache.tar.gz")
			Log("Uploading %q provider data cache", provider)

			file.EnsureDir(dir)
			if file.Exists(archive) {
				file.Delete(archive)
			}
			Run(fmt.Sprintf("%s cache status -p %s", grypeDB, provider))
			Run(fmt.Sprintf("%s cache backup -v --path %s -p %s", grypeDB, archive, provider))
			Run(fmt.Sprintf("oras push %s -v %s %s --annotation org.opencontainers.image.source=%s",
				orasFlags(), ref, archive, sourceRepoURL))
			Run(fmt.Sprintf("crane tag %s latest", ref))
			file.Delete(dir)
		},
	}
}

// downloadAllProviderCacheWorkers bounds how many provider caches download at
// once; downloadProviderCacheAttempts is the per-provider retry budget.
const (
	downloadAllProviderCacheWorkers = 5
	downloadProviderCacheAttempts   = 2
)

// downloadAllProviderCacheTask pulls and restores every provider's cache
// concurrently (bounded worker pool, with a periodic progress report). The set
// of providers comes from $PROVIDERS_USED if set, otherwise from the grype-db
// provider list. Fails the task if any provider could not be restored.
func downloadAllProviderCacheTask() Task {
	return Task{
		Name:        "download-all-provider-cache",
		Description: "download and restore all provider data caches",
		Run: func() {
			providers := providersToDownload()
			log.Info("providers: %v", providers)

			var (
				mu     sync.Mutex
				status = make(map[string]string, len(providers))
				failed []string
				wg     sync.WaitGroup
				sem    = make(chan struct{}, downloadAllProviderCacheWorkers)
			)
			setStatus := func(p, s string) { mu.Lock(); status[p] = s; mu.Unlock() }

			// periodic progress reporter, stopped once all downloads finish
			stop := make(chan struct{})
			go reportDownloadProgress(&mu, status, len(providers), stop)

			for _, p := range providers {
				wg.Add(1)
				sem <- struct{}{}
				go func(provider string) {
					defer wg.Done()
					defer func() { <-sem }()

					var lastErr error
					for attempt := 0; attempt < downloadProviderCacheAttempts; attempt++ {
						if attempt > 0 {
							setStatus(provider, "retrying")
							time.Sleep(2 * time.Second)
						} else {
							setStatus(provider, "downloading")
						}
						if lastErr = downloadProviderCache(provider, "latest"); lastErr == nil {
							break
						}
					}

					if lastErr != nil {
						setStatus(provider, "failed")
						mu.Lock()
						failed = append(failed, provider)
						mu.Unlock()
						log.Error(fmt.Errorf("[FAIL] %s (after %d attempts): %w", provider, downloadProviderCacheAttempts, lastErr))
						return
					}
					setStatus(provider, "done")
					log.Info("[OK] %s", provider)
				}(p)
			}

			wg.Wait()
			close(stop)

			if len(failed) > 0 {
				sort.Strings(failed)
				lang.Throw(fmt.Errorf("failed providers: %s", strings.Join(failed, ", ")))
			}
			log.Info("Successfully restored %d provider caches", len(providers))
		},
	}
}

// providersToDownload returns the providers to fetch, preferring the
// $PROVIDERS_USED environment variable (a JSON or python-repr list) and falling
// back to querying the grype-db CLI.
func providersToDownload() []string {
	if env := os.Getenv("PROVIDERS_USED"); strings.TrimSpace(env) != "" {
		log.Info("using values from $PROVIDERS_USED environment variable")
		return parseProviderList(env)
	}
	log.Info("invoking grype-db to get list of providers to use")
	return parseProviderList(Run(grypeDB+" list-providers -q -o json", run.Quiet()))
}

// parseProviderList parses a list of provider names. It accepts a JSON array
// (["a","b"]) and tolerates a python-repr list (['a', 'b']), matching the
// behavior of the script this replaced.
func parseProviderList(s string) []string {
	s = strings.TrimSpace(s)
	var providers []string
	if json.Unmarshal([]byte(s), &providers) == nil {
		return providers
	}
	for _, part := range strings.Split(strings.Trim(s, "[]"), ",") {
		if p := strings.Trim(strings.TrimSpace(part), `'"`); p != "" {
			providers = append(providers, p)
		}
	}
	return providers
}

// reportDownloadProgress logs which providers are still downloading every 5s
// until stop is closed.
func reportDownloadProgress(mu *sync.Mutex, status map[string]string, total int, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			mu.Lock()
			completed := 0
			var active []string
			for p, s := range status {
				switch s {
				case "done", "failed":
					completed++
				case "downloading":
					active = append(active, p)
				case "retrying":
					active = append(active, p+" (retry)")
				}
			}
			mu.Unlock()
			if len(active) > 0 {
				sort.Strings(active)
				log.Info("[progress] %d/%d complete, downloading: %s", completed, total, strings.Join(active, ", "))
			}
		}
	}
}

// ciCheckTask asserts the task is running in CI (guards destructive/publishing tasks).
func ciCheckTask() Task {
	return Task{
		Name:        "ci-check",
		Description: "assert the current execution is in a CI environment",
		Run: func() {
			if os.Getenv("CI") == "" {
				lang.Throw(fmt.Errorf("this task should ONLY be run in CI"))
			}
		},
	}
}

// cliTasks runs the CLI test suites. `cli` (go + python) hooks onto `test`.
func cliTasks() Task {
	return Task{
		Name:         "cli",
		Description:  "run all CLI tests (go + python)",
		Dependencies: Deps("cli-go", "cli-python"),
		RunsOn:       lang.List("test"),
		Tasks: []Task{
			{
				Name:        "cli-go",
				Description: "run go CLI tests against the snapshot binary",
				Run: func() {
					bin := snapshotBinary()
					Run("chmod 755 " + bin)
					Run(bin + " version")
					Run("go test -count=1 -timeout=15m -v ./test/cli",
						run.Env("GRYPE_DB_BINARY_LOCATION", lang.Return(filepath.Abs(bin))))
				},
			},
			{
				Name:        "cli-python",
				Description: "run python CLI tests",
				Run:         func() { file.InDir("manager", func() { Run("uv run make cli") }) },
			},
		},
	}
}

// snapshotBinary resolves the snapshot binary for the current OS. In CI the
// snapshot dir is restored from cache at snapshot/<os>-build_<os>_amd64_v1/<bin>
// (mirrors the old Makefile $(SNAPSHOT_BIN)); locally we build a single-target
// snapshot on demand and glob for the produced binary.
func snapshotBinary() string {
	exact := fmt.Sprintf("%s/%s-build_%s_amd64_v1/%s", snapshotBn, runtime.GOOS, runtime.GOOS, project)
	if file.Exists(exact) {
		return exact
	}
	log.Info("no prebuilt snapshot binary at %s; building single-target snapshot", exact)
	Run("go run -C .make . snapshot:single-target")
	matches := file.FindAll(fmt.Sprintf("%s/*/%s", snapshotBn, project))
	for _, m := range matches {
		if strings.Contains(m, runtime.GOOS) {
			return m
		}
	}
	if len(matches) > 0 {
		return matches[0]
	}
	lang.Throw(fmt.Errorf("no snapshot binary found under %s/", snapshotBn))
	return ""
}

// dbAcceptanceTask runs the DB acceptance test harness for a schema version.
func dbAcceptanceTask() Task {
	return Task{
		Name:        "db-acceptance",
		Description: "run DB acceptance tests (param: schema)",
		Run: func() {
			schema := param("schema")
			Log("Running DB acceptance tests (schema=%s)", schema)
			Run("uv run ./test/db/acceptance.sh " + strings.TrimSpace(schema))
		},
	}
}

// managerTasks wraps the python ./manager subproject. Its static-analysis and
// test suites hook onto the top-level `static-analysis` and `test` labels so a
// full `make static-analysis` / `make test` exercises python as well.
func managerTasks() Task {
	inManager := func(cmd string) func() {
		return func() { file.InDir("manager", func() { Run(cmd) }) }
	}
	return Task{
		Tasks: []Task{
			{
				Name:        "bootstrap-python",
				Description: "install python manager dependencies",
				Run:         inManager("make bootstrap"),
			},
			{
				Name:        "unit-python",
				Description: "run python unit tests",
				Run:         inManager("make unit"),
			},
			{
				Name:        "static-analysis-python",
				Description: "run python static analysis",
				RunsOn:      lang.List("static-analysis"),
				Run:         inManager("uv run make static-analysis"),
			},
			{
				Name:        "test-python",
				Description: "run python tests",
				RunsOn:      lang.List("test"),
				Run:         inManager("uv run make test"),
			},
		},
	}
}

// generateProcessorCodeTask regenerates ./pkg/process code and reformats.
func generateProcessorCodeTask() Task {
	return Task{
		Name:        "generate-processor-code",
		Description: "generate processor code",
		Run: func() {
			Run("go generate ./pkg/process")
			Run("go run -C .make . format")
		},
	}
}

// cleanDBTask removes built DB artifacts; hooks onto `clean`.
func cleanDBTask() Task {
	return Task{
		Name:        "clean-db",
		Description: "remove built DB artifacts",
		RunsOn:      lang.List("clean"),
		Run: func() {
			for _, p := range append(
				[]string{"build", "metadata.json", "listing.json", "vulnerability.db"},
				file.FindAll("vulnerability-db*.tar.gz")...,
			) {
				if file.Exists(p) {
					file.Delete(p)
				}
			}
		},
	}
}

// clearTestCacheTask deletes cached tar fixtures used by the test suites.
func clearTestCacheTask() Task {
	return Task{
		Name:        "clear-test-cache",
		Description: "delete cached test tar fixtures",
		Run: func() {
			Run(`bash -c "find . -type f -wholename '**/test-fixtures/tar-cache/*.tar' -delete"`)
		},
	}
}
