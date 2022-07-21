package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

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
	key := args[0]
	value := args[1]
	if !checkValidKey(key) {
		return fmt.Errorf("not a valid key: " + key)
	}

	configFile := filepath.Join(viper.GetString("LOCAL_CONFIG_DIR"), viper.GetString("LOCAL_PRESETS_FILE_NAME"))

	if !fileExists(configFile) {
		var file, err = os.Create(configFile)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(configFile, []byte("{}"), 0644)
		if err != nil {
			return err
		}
		file.Close()
	}
	return UpdateConfigFileJSON(configFile, key, value)
}

func UpdateConfigFileJSON(jsonFile string, key string, value string) error {
	// Read json buffer from jsonFile
	var config map[string]interface{}

	readBytes, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return err
	}

	err = json.Unmarshal(readBytes, &config)
	if err != nil {
		return err
	}

	config[key] = value

	// Convert golang object back to byte
	writeBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	// Write back to file
	err = ioutil.WriteFile(jsonFile, writeBytes, 0644)
	return err
}

func checkValidKey(key string) bool {
	for _, k := range viper.AllKeys() {
		if k == key {
			return true
		}
	}
	return false
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}