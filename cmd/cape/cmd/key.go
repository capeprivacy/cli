package cmd

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/sdk"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Displays the Cape Key (Public Key) which is unqiue to your account. ",
	Long: `Displays the Cape Key (Public Key) which is unique to your account.

The key is used by "cape encrypt" to encrypt data. "cape
encrypt" calls "cape key" automatically. The first call to
"cape key" will download the public key from the enclave and
save it. Subsequent calls will display the key from a local
file. The downloaded key is signed by the enclave, and the
signature is verified before the key is saved.
`,
	RunE: key,
}

func init() {
	rootCmd.AddCommand(keyCmd)

	keyCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against, used while getting key for the first time")
	keyCmd.PersistentFlags().StringP("token", "t", "", "authorization token to use")
}

func key(cmd *cobra.Command, args []string) error {
	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		t, err := authTokenFunc()
		if err != nil {
			return err
		}

		token = t
	}

	keyReq, err := GetKeyRequest(pcrSlice, token)
	if err != nil {
		return err
	}

	capeKey, err := keyFunc(keyReq)
	if err != nil {
		return err
	}

	// The pem file could then be used to encrypt with openssl or elsewhere, independent of Cape...
	//  ...but NOTE that Cape will only support decryption if envelope encryption is used.
	p, err := x509.ParsePKIXPublicKey(capeKey)
	if err != nil {
		return UserError{Msg: "error: key in unexpected format", Err: err}
	}

	m, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return UserError{Msg: "error: key in unexpected format", Err: err}
	}

	if _, err := cmd.OutOrStdout().Write(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: m,
	})); err != nil {
		return err
	}

	return nil
}

func GetKeyRequest(pcrSlice []string, token string) (sdk.KeyRequest, error) {
	return sdk.KeyRequest{
		URL:          C.EnclaveHost,
		Insecure:     C.Insecure,
		FunctionAuth: entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken, Token: token},
		ConfigDir:    C.LocalConfigDir,
		CapeKeyFile:  C.LocalCapeKeyFileName,
		PcrSlice:     pcrSlice,
	}, nil
}

var authTokenFunc = getAuthToken
var keyFunc = sdk.Key
