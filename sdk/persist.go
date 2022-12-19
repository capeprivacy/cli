package sdk

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func PersistFile(configDir, filename string, data []byte) error {
	fullPath := filepath.Join(configDir, filename)
	log.Debugf("saving data to directory %s", configDir)

	err := os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}

	err = os.Chmod(configDir, 0700)
	if err != nil {
		return err
	}

	err = os.WriteFile(fullPath, data, 0600)
	if err != nil {
		return err
	}
	log.Debugf("data saved to %s", filename)

	// If file or directory previously existed, enforce limited permissions
	err = os.Chmod(fullPath, 0600)
	if err != nil {
		return err
	}

	return nil
}

func readFile(directory, capeKeyFile string) ([]byte, error) {
	fullPath := filepath.Join(directory, capeKeyFile)
	log.Debug("Reading file ", capeKeyFile)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	return data, nil
}
