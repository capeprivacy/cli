package cmd

import (
	"encoding/json"
	"fmt"

	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/protocol"
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
	capeKey, err := getCapeKey()
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

func getCapeKey() ([]byte, error) {
	var capeKey, err = readCapeKey()
	if err != nil {
		// If the key file isn't present we download it, but log this error anyway in case something else happened.
		log.Debug("Unable to open cape key file: %w", err)

		capeKey, err = downloadAndSaveKey()
		if err != nil {
			return nil, err
		}
	}

	return capeKey, nil
}

func downloadAndSaveKey() ([]byte, error) {
	log.Debug("Downloading cape key...")

	_, userData, err := ConnectAndAttest()
	if err != nil {
		log.Println("failed to attest")
		return nil, err
	}

	if userData.CapeKey == nil {
		return nil, fmt.Errorf("did not receive cape key")
	}

	err = persistCapeKey(userData.CapeKey)
	if err != nil {
		log.Println("failed saving cape key")
		return nil, err
	}

	return userData.CapeKey, nil
}

// TODO: Run, deploy and test could use this function.
func ConnectAndAttest() (*attest.AttestationDoc, *attest.AttestationUserData, error) {
	url := C.EnclaveHost
	insecure := C.Insecure

	t, err := getAuthToken()
	if err != nil {
		return nil, nil, err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}

	endpoint := fmt.Sprintf("%s/v1/key", url)

	authProtocolType := "cape.runtime"

	c, res, err := websocketDial(endpoint, insecure, authProtocolType, auth.Token)
	if err != nil {
		log.Error("error dialing websocket: ", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if res != nil {
			fmt.Println("res.Body", res.Body)
			fmt.Println("res", res)
			var e ErrorMsg
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				return nil, nil, err
			}
			res.Body.Close()
			return nil, nil, fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
		}
		return nil, nil, err
	}
	defer c.Close()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, nil, err
	}

	p := protocol.Protocol{Websocket: c}

	req := entities.StartRequest{Nonce: []byte(nonce), AuthToken: auth.Token}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error writing run request")
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Println("error reading attestation doc")
		return nil, nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return nil, nil, err
	}

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, userData, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Println("error attesting")
		return nil, nil, err
	}

	return doc, userData, nil
}

func persistCapeKey(capeKey []byte) error {
	log.Debug("Saving cape key...")

	err := os.MkdirAll(C.LocalConfigDir, os.ModePerm)
	if err != nil {
		return err
	}

	capeKeyFile := filepath.Join(C.LocalConfigDir, C.LocalCapeKeyFileName)

	err = os.WriteFile(capeKeyFile, capeKey, 0644)
	if err != nil {
		return err
	}

	log.Debug("Cape Key saved to ", capeKeyFile)

	return nil
}

func readCapeKey() ([]byte, error) {
	capeKeyFile := filepath.Join(C.LocalConfigDir, C.LocalCapeKeyFileName)

	log.Debug("Reading Cape Key from ", capeKeyFile)

	capeKey, err := os.ReadFile(filepath.Join(C.LocalConfigDir, C.LocalCapeKeyFileName))
	if err != nil {
		return nil, err
	}

	return capeKey, nil
}
