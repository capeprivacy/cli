package sdk

import (
	"fmt"

	"os"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
)

type KeyRequest struct {
	URL          string
	FunctionAuth entities.FunctionAuth
	ConfigDir    string
	CapeKeyFile  string
	PcrSlice     []string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

func Key(keyReq KeyRequest) ([]byte, error) {
	var capeKey, err = readCapeKey(keyReq.CapeKeyFile)
	if err != nil {
		// If the key file isn't present we download it, but log this error anyway in case something else happened.
		log.Debugf("Unable to open cape key file: %s", err)

		capeKey, err = downloadAndSaveKey(keyReq)
		if err != nil {
			return nil, err
		}
	}

	return capeKey, nil
}

func downloadAndSaveKey(keyReq KeyRequest) ([]byte, error) {
	log.Debug("Downloading cape key...")

	_, userData, err := ConnectAndAttest(keyReq)
	if err != nil {
		log.Println("failed to attest")
		return nil, err
	}

	if userData.CapeKey == nil {
		return nil, fmt.Errorf("did not receive cape key")
	}

	err = persistCapeKey(keyReq.ConfigDir, keyReq.CapeKeyFile, userData.CapeKey)
	if err != nil {
		log.Println("failed saving cape key")
		return nil, err
	}

	return userData.CapeKey, nil
}

// TODO: Run, deploy and test could use this function.
func ConnectAndAttest(keyReq KeyRequest) (*attest.AttestationDoc, *attest.AttestationUserData, error) {
	endpoint := fmt.Sprintf("%s/v1/key", keyReq.URL)

	authProtocolType := "cape.runtime"
	auth := keyReq.FunctionAuth
	if auth.Type == entities.AuthenticationTypeFunctionToken {
		authProtocolType = "cape.function"
	}

	conn, err := doDial(endpoint, keyReq.Insecure, authProtocolType, auth.Token)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		conn.Close()
	}()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, nil, err
	}

	p := getProtocol(conn)

	req := entities.StartRequest{Nonce: []byte(nonce)}
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

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(keyReq.PcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return nil, nil, err
	}

	return doc, userData, nil
}

func persistCapeKey(configDir string, capeKeyFile string, capeKey []byte) error {
	log.Debug("Saving cape key...")

	err := os.MkdirAll(configDir, os.ModePerm)
	if err != nil {
		return err
	}

	err = os.WriteFile(capeKeyFile, capeKey, 0644)
	if err != nil {
		return err
	}

	log.Debug("Cape Key saved to ", capeKeyFile)

	return nil
}

func readCapeKey(capeKeyFile string) ([]byte, error) {
	log.Debug("Reading Cape Key from ", capeKeyFile)

	capeKey, err := os.ReadFile(capeKeyFile)
	if err != nil {
		return nil, err
	}

	return capeKey, nil
}
