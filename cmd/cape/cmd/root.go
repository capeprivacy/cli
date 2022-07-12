package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/capeprivacy/cli/config"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

var C config.Config

var version = "unknown"

var cfgFile string

type PresetArgs struct {
	URL      string `json:"url"`
	Verbose  bool   `json:"verbose"`
	Insecure bool   `json:"insecure"`
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cape",
	Short: "Cape command",
	Long:  `Cape commandline tool`,
}

// ExecuteCLI adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func ExecuteCLI() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/capeprivacy/cape.yaml)")
	rootCmd.PersistentFlags().StringP("url", "u", "https://newdemo.capeprivacy.com", "Cape Cloud URL")
	rootCmd.PersistentFlags().Bool("insecure", false, "!!! For development only !!! Disable TLS certificate verification.")
	if err := rootCmd.PersistentFlags().MarkHidden("insecure"); err != nil {
		log.Error("flag not found")
		cobra.CheckErr(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Set up environment configs.
	viper.SetEnvPrefix("CAPE")

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
	home, err := os.UserHomeDir()
	cobra.CheckErr(err)
	viper.SetDefault("LOCAL_AUTH_DIR", home+"/.config/cape")

	if err := viper.BindEnv("LOCAL_AUTH_FILE_NAME"); err != nil {
		log.Error("failed to bind environment variable: LOCAL_AUTH_FILE_NAME.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_AUTH_FILE_NAME", "auth")

	if err := viper.BindEnv("LOCAL_PRESETS_FILE_NAME"); err != nil {
		log.Error("failed to bind environment variable: LOCAL_PRESETS_FILE_NAME.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_PRESETS_FILE_NAME", "presets")

	if err := viper.BindEnv("DEV_DISABLE_SSL"); err != nil {
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("DEV_DISABLE_SSL", false)

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".client" (without extension).
		viper.AddConfigPath(home + "/.config/capeprivacy")
		viper.SetConfigType("yaml")
		viper.SetConfigName("cape")
	}
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// GetString takes into account the prefix if environment variables are specified.
	C.Audience = viper.GetString("AUDIENCE")
	C.Hostname = viper.GetString("HOSTNAME")
	C.ClientID = viper.GetString("CLIENT_ID")
	C.LocalAuthDir = viper.GetString("LOCAL_AUTH_DIR")
	C.LocalAuthFileName = viper.GetString("LOCAL_AUTH_FILE_NAME")
	C.LocalPresetsFileName = viper.GetString("LOCAL_PRESETS_FILE_NAME")
	C.Insecure = viper.GetBool("DEV_DISABLE_SSL")
}

func getPresetArgs() (*PresetArgs, error) {
	file := filepath.Join(C.LocalAuthDir, C.LocalPresetsFileName)
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return &PresetArgs{}, nil
	}

	presetFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer presetFile.Close()

	byteValue, err := ioutil.ReadAll(presetFile)
	if err != nil {
		return nil, err
	}

	var presets PresetArgs
	err = json.Unmarshal(byteValue, &presets)
	if err != nil {
		return nil, err
	}

	return &presets, nil
}
