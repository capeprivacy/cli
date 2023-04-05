package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	goVersion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/capeprivacy/cli/config"
	"github.com/capeprivacy/cli/render"
)

var C config.Config

var version = "unknown"

type UserError struct {
	Msg string
	Err error
}

func (e UserError) Error() string {
	return fmt.Sprintf("%s: %s", e.Msg, e.Err.Error())
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cape",
	Short: "Cape command",
	Long:  `Cape commandline tool`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		o, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}

		setRenderer(cmd, o)

		log.SetFormatter(&PlainFormatter{})

		v, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}

		if v {
			log.SetLevel(log.DebugLevel)
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return err
		}

		if insecure {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}

		return nil
	},
}

type Release struct {
	TagName string `json:"tag_name"`
}

func checkForUpdate(ctx context.Context) (*Release, error) {
	version := getVersion()
	if strings.HasPrefix(version, "(devel)") {
		// don't check in dev
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/capeprivacy/cli/releases/latest", nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	v, err := goVersion.NewVersion(release.TagName)
	if err != nil {
		return nil, err
	}

	myVersion, err := goVersion.NewVersion(version)
	if err != nil {
		return nil, err
	}

	if v.GreaterThan(myVersion) {
		return &release, nil
	}

	return nil, nil
}

// ExecuteCLI adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func ExecuteCLI() {
	ctx := context.Background()
	updateCtx, updateCancel := context.WithCancel(ctx)
	defer updateCancel()
	releaseCh := make(chan *Release)
	go func() {
		u, _ := checkForUpdate(updateCtx)
		// we don't care if there is an error
		releaseCh <- u
	}()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1) //nolint:gocritic
	}

	// give up on trying to see if there is an update
	updateCancel()
	if release := <-releaseCh; release != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\nThere is a new version (%s) of the Cape CLI available, you can download it at https://github.com/capeprivacy/cli/releases/latest\n", release.TagName)
		_, _ = fmt.Fprintf(os.Stderr, "Or upgrade by running \n\tcurl -fsSL https://raw.githubusercontent.com/capeprivacy/cli/main/install.sh | sh")
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringP("config", "c", "$HOME/.config/cape/presets.json", "config file")
	rootCmd.PersistentFlags().StringP("url", "u", "https://app.capeprivacy.com", "cape cloud URL")
	rootCmd.PersistentFlags().Bool("insecure", false, "!!! For development only !!! Disable TLS certificate verification.")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringP("output", "o", "plain", "output format")

	if err := rootCmd.PersistentFlags().MarkHidden("url"); err != nil {
		log.Error("flag not found")
		cobra.CheckErr(err)
	}

	if err := rootCmd.PersistentFlags().MarkHidden("insecure"); err != nil {
		log.Error("flag not found")
		cobra.CheckErr(err)
	}

	if err := viper.BindPFlag("AUTH_HOST", rootCmd.PersistentFlags().Lookup("url")); err != nil {
		log.Error("failed to bind cli argument.")
		cobra.CheckErr(err)
	}
	if err := viper.BindPFlag("ENCLAVE_HOST", rootCmd.PersistentFlags().Lookup("url")); err != nil {
		log.Error("failed to bind cli argument.")
		cobra.CheckErr(err)
	}
	if err := viper.BindPFlag("DEV_DISABLE_SSL", rootCmd.PersistentFlags().Lookup("insecure")); err != nil {
		log.Error("failed to bind cli argument.")
		cobra.CheckErr(err)
	}
	if err := viper.BindPFlag("LOCAL_PRESETS_FILE_NAME", rootCmd.PersistentFlags().Lookup("config")); err != nil {
		log.Error("failed to bind cli argument.")
		cobra.CheckErr(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Get config path and files from env
	if err := viper.BindEnv("LOCAL_CONFIG_DIR"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	home, err := os.UserHomeDir()
	cobra.CheckErr(err)
	viper.SetDefault("LOCAL_CONFIG_DIR", home+"/.config/cape")

	if err := viper.BindEnv("LOCAL_PRESETS_FILE_NAME"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_PRESETS_FILE_NAME", "presets.json")

	// Read in config parameters from file
	viper.AddConfigPath(viper.GetString("LOCAL_CONFIG_DIR"))
	viper.SetConfigName(viper.GetString("LOCAL_PRESETS_FILE_NAME"))
	viper.SetConfigType("json")

	if err := readConfFile(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file found but not valid
			log.Error("failed to read config params.")
			cobra.CheckErr(err)
		}
	}

	viper.SetEnvPrefix("CAPE")
	viper.AutomaticEnv()

	//  Bind env variables
	if err := viper.BindEnv("AUDIENCE"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("AUDIENCE", "https://app.capeprivacy.com/v1/")

	if err := viper.BindEnv("AUTH_HOST"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("AUTH_HOST", "https://app.capeprivacy.com")

	if err := viper.BindEnv("ENCLAVE_HOST"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("ENCLAVE_HOST", "https://app.capeprivacy.com")

	if err := viper.BindEnv("CLIENT_ID"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("CLIENT_ID", "oXITxpCdjvRYSDJtaMeycvveqE9qadUS")

	if err := viper.BindEnv("LOCAL_AUTH_FILE_NAME"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_AUTH_FILE_NAME", "auth")

	if err := viper.BindEnv("LOCAL_CAPE_KEY_FILE_NAME"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_CAPE_KEY_FILE_NAME", "capekey.pub.der")

	if err := viper.BindEnv("DEV_DISABLE_SSL"); err != nil {
		log.Error("failed to bind config variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("DEV_DISABLE_SSL", false)

	C.Audience = viper.GetString("AUDIENCE")
	C.AuthHost = strings.TrimSuffix(viper.GetString("AUTH_HOST"), "/")
	C.EnclaveHost = strings.TrimSuffix(viper.GetString("ENCLAVE_HOST"), "/")
	C.ClientID = viper.GetString("CLIENT_ID")
	C.LocalConfigDir = viper.GetString("LOCAL_CONFIG_DIR")
	C.LocalAuthFileName = viper.GetString("LOCAL_AUTH_FILE_NAME")
	C.LocalCapeKeyFileName = viper.GetString("LOCAL_CAPE_KEY_FILE_NAME")
	C.Insecure = viper.GetBool("DEV_DISABLE_SSL")

	if err != nil {
		log.Error("failed to set config parameters.")
		cobra.CheckErr(err)
	}
}

func setRenderer(cmd *cobra.Command, s string) {
	ctx := cmd.Context()

	var r render.Renderer
	r = render.Print{}
	switch s {
	case "json":
		r = &render.JSON{}
	case "human":
		fallthrough
	default:
		if t, ok := tmpl[cmd.Name()]; ok {
			r = render.NewTemplate(t)
		}
	}

	cmd.SetContext(render.WithCtx(ctx, r))
}

var tmpl = make(map[string]string)

func registerTemplate(name, template string) {
	tmpl[name] = template
}

var readConfFile = viper.ReadInConfig
