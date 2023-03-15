package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/bus"
)

func async(f func() error) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		if err := f(); err != nil {
			errs <- err
		}
		bus.Exit()
	}()

	return errs
}

func commonConfiguration(app *application.Application, cmd *cobra.Command, opts options.Interface) {
	if opts != nil {
		opts.AddFlags(cmd.Flags())

		if app != nil {
			// we want to be able to attach config binding information to the help output
			cmd.SetHelpFunc(func(passCmd *cobra.Command, args []string) {
				fmt.Println(">>> help func", cmd.Use, passCmd.Use)
				_ = app.Setup(opts)(cmd, args)
				cmd.Parent().HelpFunc()(cmd, args)
			})
		}
	}

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetHelpTemplate(`{{if (or .Long .Short)}}{{.Long}}{{if not .Long}}{{.Short}}{{end}}

{{end}}Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if .HasExample}}

{{.Example}}{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{if not .CommandPath}}Global {{end}}Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if (and .HasAvailableInheritedFlags (not .CommandPath))}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{if .CommandPath}}{{.CommandPath}} {{end}}[command] --help" for more information about a command.{{end}}
`)
}
