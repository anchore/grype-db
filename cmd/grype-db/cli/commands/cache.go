package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/grype-db/cmd/grype-db/application"
)

func Cache(_ *application.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "manage the local pull cache",
		Args:  cobra.NoArgs,
	}

	commonConfiguration(nil, cmd, nil)
	return cmd
}
