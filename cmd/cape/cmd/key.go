package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/sdk"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Retrieve a public key, signed by the enclave, which can encrypt data to later run",
	RunE:  key,
}

func init() {
	rootCmd.AddCommand(keyCmd)
}

func key(cmd *cobra.Command, args []string) error {
	keyReq, err := GetKeyRequest()
	if err != nil {
		return err
	}

	capeKey, err := sdk.Key(keyReq)
	if err != nil {
		return err
	}

	// TODO: It may be best to display the key in PEM format.
	// This is the DER format that KMS gives us, and that we use directly.
	// A user could convert it to PEM with openssl: openssl pkey -pubin -inform der -in ~/.config/cape/capekey.pub.der -out capekey.pub.pem
	// The pem file could then be used to encrypt with openssl or elsewhere, independent of Cape...
	//  ...but NOTE that Cape will only support decryption if envelope encryption is used.
	fmt.Println(capeKey)

	return nil
}

func GetKeyRequest() (sdk.KeyRequest, error) {
	url := C.EnclaveHost
	insecure := C.Insecure

	t, err := getAuthToken()
	if err != nil {
		return sdk.KeyRequest{}, err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}

	configDir := C.LocalConfigDir
	capeKeyFile := filepath.Join(C.LocalConfigDir, C.LocalCapeKeyFileName)

	return sdk.KeyRequest{
		URL:          url,
		Insecure:     insecure,
		FunctionAuth: auth,
		ConfigDir:    configDir,
		CapeKeyFile:  capeKeyFile,
	}, nil
}
