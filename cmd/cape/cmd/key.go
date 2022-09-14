package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/sdk"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Displays the Cape Key (Public Key) which is unqiue to your account. ",
	Long: "Displays the Cape Key (Public Key) which is unqiue to your account.\n" +
		"The key is used by \"cape encrypt\" to encrypt data. \"cape encrypt\" calls \"cape key\" automatically. " +
		"The first call to \"cape key\" will download the public key from the enclave and save it. Subsequent calls will display the key from a local file. " +
		"The downloaded key is signed by the enclave, and the signature is verified before the key is saved. " +
		"Example: \"cape key\".\n",
	RunE: key,
}

func init() {
	rootCmd.AddCommand(keyCmd)

	keyCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against, used while getting key for the first time")
}

func key(cmd *cobra.Command, args []string) error {
	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	keyReq, err := GetKeyRequest(pcrSlice)
	if err != nil {
		return err
	}

	capeKey, err := sdk.Key(keyReq)
	if err != nil {
		return err
	}

	// The pem file could then be used to encrypt with openssl or elsewhere, independent of Cape...
	//  ...but NOTE that Cape will only support decryption if envelope encryption is used.
	p, err := x509.ParsePKIXPublicKey(capeKey)
	if err != nil {
		return err
	}

	m, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return err
	}

	fmt.Println(string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: m,
	})))

	return nil
}

func GetKeyRequest(pcrSlice []string) (sdk.KeyRequest, error) {
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
		PcrSlice:     pcrSlice,
	}, nil
}
