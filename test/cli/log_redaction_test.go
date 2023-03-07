package cli

import (
	"strings"
	"testing"
)

func TestLogRedaction_CommandConfigs(t *testing.T) {
	secretValue := "topsy-kretts"
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{name: "pull"},
		{name: "build"},
		{name: "cache status"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append(strings.Split(test.name, " "), "--dry-run", "-vv", "-c", "test-fixtures/grype-db-config-with-secrets.yaml")
			args = append(args, test.args...)
			cmd, stdout, stderr := runGrypeDB(t, test.env, args...)
			assertions := []traitAssertion{
				assertLoggingLevel("debug"),
				assertNotInOutput(secretValue),
			}
			assertions = append(assertions, test.assertions...)
			for _, traitFn := range assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}
