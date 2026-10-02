package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/cmd/grype-db/application"
)

func TestRoot_Name(t *testing.T) {
	cmd := Root(application.New())
	// cobra derives the program name used in generated shell completion
	// scripts (e.g. `grype-db completion bash`) from cmd.Name(), which
	// parses Use up to the first space. An empty Use here produces a
	// completion script with no program name, which fails when sourced.
	require.Equal(t, "grype-db", cmd.Name())
}
