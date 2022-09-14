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

	keyCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
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

	// TODO: It may be best to display the key in PEM format.
	// This is the DER format that KMS gives us, and that we use directly.
	// A user could convert it to PEM with openssl: openssl pkey -pubin -inform der -in ~/.config/cape/capekey.pub.der -out capekey.pub.pem
	// The pem file could then be used to encrypt with openssl or elsewhere, independent of Cape...
	//  ...but NOTE that Cape will only support decryption if envelope encryption is used.
	fmt.Println(capeKey)

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
