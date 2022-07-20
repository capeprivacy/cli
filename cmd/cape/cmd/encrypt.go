package cmd

import (
	"fmt"

	"github.com/capeprivacy/cli/capeencrypt"
	"github.com/capeprivacy/cli/entities"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt <data>",
	Short: "Encrypt data with Cape",
	RunE:  Encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)
}

func Encrypt(cmd *cobra.Command, args []string) error {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		return fmt.Errorf("flag not found: %w", err)
	}

	insecure, err := insecure(cmd)
	if err != nil {
		return err
	}

	token, err := authToken()
	if err != nil {
		return err
	}

	input := args[0]
	res, err := encrypt(entities.EncryptRequest{
		AuthToken: token,
		Data:      input,
	}, u+"/v1/encrypt", insecure)
	if err != nil {
		return err
	}

	log.Info(res.Value)
	return nil
}

var encrypt = capeencrypt.Encrypt
