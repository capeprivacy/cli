package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

var cfgFile string

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
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetEnvPrefix("CLI")
	viper.BindEnv("HOSTNAME")
	viper.BindEnv("CLIENT_ID")
	viper.BindEnv("AUDIENCE")
	viper.BindEnv("LOCAL_AUTH_DIR")
	viper.BindEnv("LOCAL_AUTH_FILE_NAME")

	// Testing
	audience := viper.Get("AUDIENCE")
	fmt.Printf("audience is: %s", audience)
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".client" (without extension).
		viper.AddConfigPath(home + "/.config/capeprivacy")
		viper.SetConfigType("yaml")
		viper.SetConfigName("cape")
		viper.WriteConfig()
	}
	viper.SafeWriteConfigAs("./")
	viper.AutomaticEnv() // read in environment variables that match
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
