package cmd

import (
	"fmt"
	"os"

	"github.com/capeprivacy/cli/config"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

var C config.Config

var version = "unknown"
var cfgFile string

type PlainFormatter struct {
}

func (f *PlainFormatter) Format(entry *log.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s\n", entry.Message)), nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cape",
	Short: "Cape command",
	Long:  `Cape commandline tool`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		log.SetFormatter(&PlainFormatter{})
		v, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}

		if v {
			log.SetLevel(log.DebugLevel)
		}

		return nil
	},
}

// ExecuteCLI adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func ExecuteCLI() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/cape/cape.yaml)")
	rootCmd.PersistentFlags().StringP("url", "u", "https://newdemo.capeprivacy.com", "Cape Cloud URL")
	rootCmd.PersistentFlags().Bool("insecure", false, "!!! For development only !!! Disable TLS certificate verification.")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	if err := rootCmd.PersistentFlags().MarkHidden("insecure"); err != nil {
		log.Error("flag not found")
		cobra.CheckErr(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	home, err := os.UserHomeDir()
	cobra.CheckErr(err)
	viper.SetDefault("LOCAL_CONFIG_DIR", home+"/.config/cape")

	presets, err = LoadConfig(viper.GetString("LOCAL_CONFIG_DIR"))
	if err != nil {
		// TODO
		cobra.CheckErr(err)
	}

	// Set up environment configs.
	viper.SetEnvPrefix("CAPE")
	viper.AutomaticEnv()

	if err := viper.BindEnv("HOSTNAME"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("HOSTNAME", "https://maestro-dev.us.auth0.com")

	if err := viper.BindEnv("CLIENT_ID"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("CLIENT_ID", "yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx")

	if err := viper.BindEnv("AUDIENCE"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("AUDIENCE", "https://newdemo.capeprivacy.com/v1/")

	if err := viper.BindEnv("LOCAL_AUTH_DIR"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}

	viper.SetDefault("LOCAL_AUTH_DIR", home+"/.config/cape")

	if err := viper.BindEnv("LOCAL_AUTH_FILE_NAME"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_AUTH_FILE_NAME", "auth")

	if err := viper.BindEnv("DEV_DISABLE_SSL"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("DEV_DISABLE_SSL", false)

	// GetString takes into account the prefix if environment variables are specified.
	C.Audience = viper.GetString("AUDIENCE")
	C.Hostname = viper.GetString("HOSTNAME")
	C.ClientID = viper.GetString("CLIENT_ID")
	C.LocalConfigDir = viper.GetString("LOCAL_AUTH_DIR")
	C.LocalAuthFileName = viper.GetString("LOCAL_AUTH_FILE_NAME")
	C.Insecure = viper.GetBool("DEV_DISABLE_SSL")
}

func insecure(cmd *cobra.Command) (bool, error) {
	flag, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return false, fmt.Errorf("flag not found: %w", err)
	}
	return flag || C.Insecure, nil
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (presets config.Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("presets")
	viper.SetConfigType("env")

	err = viper.ReadInConfig()
	if err != nil {
		return config.Config{}, err
	}

	viper.SetEnvPrefix("CAPE")
	viper.AutomaticEnv()

	err = viper.Unmarshal(&presets)
	return presets, err
}
