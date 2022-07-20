package cmd

import (
	"encoding/json"
	"io/ioutil"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configCmd = &cobra.Command{
	Use:   "config key value",
	Short: "Configure and save persistent parameters for Cape",
	Long: "Configure and save persistent parameters for Cape\n" +
		"Use the configure option to set global parameters and save to a json file for later use.\n" +
		"Default is $HOME/.config/cape/presets.json",
	RunE: Config,
}

func init() {
	rootCmd.AddCommand(configCmd)
}

func Config(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		if err := cmd.Usage(); err != nil {
			return err
		}
		return nil
	}

	configFile := viper.ConfigFileUsed()
	return UpdateConfigFileJSON(configFile, args[0], args[1])
}

func UpdateConfigFileJSON(jsonFile string, key string, value string) error {
	// Read json buffer from jsonFile
	byteValue, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return err
	}

	var config map[string]interface{}
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return err
	}

	config[key] = value

	// Convert golang object back to byte
	byteValue, err = json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	// Write back to file
	err = ioutil.WriteFile(jsonFile, byteValue, 0644)
	return err
}
