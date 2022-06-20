package cmd

import (
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

var cfgFile string
var debugEnabled bool

func debug(w io.Writer, format string, a ...interface{}) {
	if !debugEnabled {
		return
	}

	_, err := w.Write(append([]byte(fmt.Sprintf("[debug] "+format, a...)), []byte("\n")...))
	if err != nil {
		panic(err)
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cape",
	Short: "Cape command",
	Long:  `Cape commandline tool`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		v, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}

		debugEnabled = v
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/capeprivacy/cape.yaml)")
	rootCmd.PersistentFlags().StringP("url", "u", "https://newdemo.capeprivacy.com", "Cape Cloud URL")
	rootCmd.PersistentFlags().Bool("insecure", false, "!!! For development only !!! Disable TLS certification.")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Set up environment configs.
	viper.SetEnvPrefix("CLI")
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
		log.Error("failed to bind environment variable.")
		cobra.CheckErr(err)
	}
	viper.SetDefault("LOCAL_AUTH_FILE_NAME", "auth")

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
}
