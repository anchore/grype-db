package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func runGrypeDB(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	return runGrypeDBCommand(t, env, true, args...)
}

func runGrypeDBCommand(t testing.TB, env map[string]string, expectError bool, args ...string) (*exec.Cmd, string, string) {
	cancel := make(chan bool, 1)
	defer func() {
		cancel <- true
	}()

	cmd := getGrypeDBCommand(t, args...)
	if env == nil {
		env = make(map[string]string)
	}

	// TODO: this does not exist... yet
	// we should not have tests reaching out for app update checks
	//env["GRYPE_DB_CHECK_FOR_APP_UPDATE"] = "false"

	timeout := func() {
		select {
		case <-cancel:
			return
		case <-time.After(60 * time.Second):
		}

		if cmd != nil && cmd.Process != nil {
			// get a stack trace printed
			err := cmd.Process.Signal(syscall.SIGABRT)
			if err != nil {
				t.Errorf("error aborting: %+v", err)
			}
		}
	}

	go timeout()

	stdout, stderr, err := runCommand(cmd, env)

	if !expectError && err != nil && stdout == "" {
		t.Errorf("error running grype-db: %+v", err)
		t.Errorf("STDOUT: %s", stdout)
		t.Errorf("STDERR: %s", stderr)

		// this probably indicates a timeout... lets run it again with more verbosity to help debug issues
		args = append(args, "-vv")
		cmd = getGrypeDBCommand(t, args...)

		go timeout()
		stdout, stderr, err = runCommand(cmd, env)

		if err != nil {
			t.Errorf("error rerunning grype-db: %+v", err)
			t.Errorf("STDOUT: %s", stdout)
			t.Errorf("STDERR: %s", stderr)
		}
	}

	return cmd, stdout, stderr
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string, error) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

func envMapToSlice(env map[string]string) (envList []string) {
	for key, val := range env {
		if key == "" {
			continue
		}
		envList = append(envList, fmt.Sprintf("%s=%s", key, val))
	}
	return
}

func getGrypeDBCommand(t testing.TB, args ...string) *exec.Cmd {
	return exec.Command(getGrypeDBBinaryLocation(t), args...)
}

func getGrypeDBBinaryLocation(t testing.TB) string {
	if os.Getenv("GRYPE_DB_BINARY_LOCATION") != "" {
		// GRYPE_DB_BINARY_LOCATION is the absolute path to the snapshot binary
		return os.Getenv("GRYPE_DB_BINARY_LOCATION")
	}
	return getGrypeDBBinaryLocationByOS(t, runtime.GOOS)
}

func getGrypeDBBinaryLocationByOS(t testing.TB, goOS string) string {
	// note: for amd64 we need to update the snapshot location with the v1 suffix
	// see : https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-builds
	archPath := runtime.GOARCH
	if runtime.GOARCH == "amd64" {
		archPath = fmt.Sprintf("%s_v1", archPath)
	}
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "darwin", "linux":
		return path.Join(repoRoot(t), fmt.Sprintf("snapshot/%s-build_%s_%s/grype-db", goOS, goOS, archPath))
	default:
		t.Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	return ""
}

func repoRoot(t testing.TB) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}
