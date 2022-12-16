package sdk

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func PersistFile(configDir, filename string, data []byte) error {
	fullPath := filepath.Join(configDir, filename)
	log.Debugf("saving data to directory %s", configDir)

	err := os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}

	uid, gid, err := getOSUser()
	if err != nil {
		return err
	}

	err = enforcePerms(configDir, uid, gid, 0700)
	if err != nil {
		return err
	}

	err = os.WriteFile(fullPath, data, 0600)
	if err != nil {
		return err
	}
	log.Debugf("data saved to %s", filename)

	// If file or directory previously existed, enforce limited permissions
	err = enforcePerms(fullPath, uid, gid, 0600)
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

func getOSUser() (int, int, error) {
	user, err := user.Current()
	if err != nil {
		return 0, 0, err
	}

	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return 0, 0, err
	}

	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return uid, 0, err
	}

	return uid, gid, nil
}

func enforcePerms(filepath string, uid, gid, permissions int) error {
	err := os.Chown(filepath, uid, gid)
	if err != nil {
		return err
	}

	err = os.Chmod(filepath, 0600)
	if err != nil {
		return err
	}
	return nil
}
