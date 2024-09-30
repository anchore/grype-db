package application

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gookit/color"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
	"gopkg.in/yaml.v3"

	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal"
	"github.com/anchore/grype-db/internal/bus"
	"github.com/anchore/grype-db/internal/eventloop"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/internal/ui"
	"github.com/anchore/grype-db/internal/utils"
)

const Name = internal.ApplicationName

type Application struct {
	Config       *Config
	subscription *partybus.Subscription
}

func New() *Application {
	return &Application{
		Config: &Config{},
	}
}

func (a *Application) Setup(opts options.Interface) func(cmd *cobra.Command, args []string) error {
	v := newViper()
	return func(cmd *cobra.Command, _ []string) error {
		// bind options to viper
		if opts != nil {
			if err := opts.BindFlags(cmd.Flags(), v); err != nil {
				return err
			}
		}

		if err := a.Config.BindFlags(cmd.Root().PersistentFlags(), v); err != nil {
			return fmt.Errorf("unable to bind persistent flags: %w", err)
		}

		if err := a.Config.Load(v); err != nil {
			return fmt.Errorf("invalid application config: %w", err)
		}

		// load initial command configuration from file...
		if a.Config.ConfigPath != "" {
			f, err := os.Open(a.Config.ConfigPath)
			if err != nil {
				return fmt.Errorf("unable to open config file: %w", err)
			}
			defer f.Close()
			contents, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("unable to read config file: %w", err)
			}
			if err := yaml.Unmarshal(contents, opts); err != nil {
				return fmt.Errorf("unable to unmarshal command elements from application config: %w", err)
			}
		}

		// setup command config...
		if opts != nil {
			err := v.Unmarshal(opts)
			if err != nil {
				return fmt.Errorf("unable to unmarshal command configuration for cmd=%q: %w", strings.TrimSpace(cmd.CommandPath()), err)
			}

			if r, ok := opts.(log.Redactable); ok {
				r.Redact()
			}
		}

		// setup logger...
		if err := setupLogger(a.Config); err != nil {
			return err
		}

		// show the app version and configuration...
		logVersion()
		logConfiguration(a.Config, opts)

		if a.Config.DryRun {
			log.Warn("dry-run mode enabled, exiting")
			os.Exit(0)
		}

		// setup the event bus (before any publishers in the workers run)...
		b := partybus.NewBus()
		bus.SetPublisher(b)
		a.subscription = b.Subscribe()

		return nil
	}
}

func (a Application) Run(ctx context.Context, errs <-chan error) error {
	if a.Config.Dev.ProfileCPU {
		defer profile.Start(profile.CPUProfile).Stop()
	} else if a.Config.Dev.ProfileMem {
		defer profile.Start(profile.MemProfile).Stop()
	}
	err := eventloop.Run(
		ctx,
		errs,
		a.subscription,
		nil,
		ui.Select(ui.Config{
			Verbose: isVerbose(a.Config.Log.Verbosity),
			Quiet:   a.Config.Log.Quiet,
			Debug:   false,
		})...,
	)

	if err != nil {
		log.Error(err.Error())
	}
	return err
}

func logConfiguration(app *Config, opts interface{}) {
	var optsStr string

	if opts != nil {
		if stringer, ok := opts.(fmt.Stringer); ok {
			optsStr = stringer.String()
		} else {
			// yaml is pretty human friendly (at least when compared to json)
			cfgBytes, err := yaml.Marshal(&opts)
			if err != nil {
				optsStr = fmt.Sprintf("%+v", opts)
			} else {
				optsStr = string(cfgBytes)
			}
		}
	}

	log.Debugf("config:\n%+v", formatConfig(app.String())+"\n"+formatConfig(optsStr))
}

func logVersion() {
	versionInfo := ReadBuildInfo()
	log.Infof("%s version: %+v", Name, versionInfo.Version)
}

func setupLogger(app *Config) error {
	cfg := logrus.Config{
		//EnableConsole: (app.Log.FileLocation == "" || app.Log.Verbosity > 0) && !app.Log.Quiet,
		EnableConsole: app.Log.Verbosity > 0 && !app.Log.Quiet,
		FileLocation:  app.Log.FileLocation,
		Level:         app.Log.Level,
	}

	l, err := logrus.New(cfg)
	if err != nil {
		return err
	}

	log.Set(l)

	return nil
}

func formatConfig(config string) string {
	return color.Magenta.Sprint(utils.Indent(strings.TrimSpace(config), "  "))
}

func isVerbose(verbosity int) (result bool) {
	pipedInput, err := isPipedInput()
	if err != nil {
		// since we can't tell if there was piped input we assume that there could be to disable the ETUI
		log.Warnf("unable to determine if there is piped input: %w", err)
		return true
	}
	// verbosity should consider if there is piped input (in which case we should not show the ETUI)
	return verbosity > 0 || pipedInput
}

// isPipedInput returns true if there is no input device, which means the user **may** be providing input via a pipe.
func isPipedInput() (bool, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false, fmt.Errorf("unable to determine if there is piped input: %w", err)
	}

	// note: we should NOT use the absence of a character device here as the hint that there may be input expected
	// on stdin, as running this application as a subprocess you would expect no character device to be present but input can
	// be from either stdin or indicated by the CLI. Checking if stdin is a pipe is the most direct way to determine
	// if there *may* be bytes that will show up on stdin that should be used for the analysis source.
	return fi.Mode()&os.ModeNamedPipe != 0, nil
}

func newViper() *viper.Viper {
	v := viper.NewWithOptions(
		viper.EnvKeyReplacer(
			strings.NewReplacer(".", "_", "-", "_"),
		),
	)

	// load environment variables
	v.SetEnvPrefix(Name)
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	return v
}
