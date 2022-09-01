package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	proto "github.com/capeprivacy/cli/protocol"
)

type protocol interface {
	WriteStart(request entities.StartRequest) error
	ReadAttestationDoc() ([]byte, error)
	ReadRunResults() (*entities.RunResults, error)
	WriteBinary([]byte) error
	WriteFunctionPublicKey(key string) error
	ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error)
}

func getProtocol(ws *websocket.Conn) protocol {
	return proto.Protocol{Websocket: ws}
}

type DeployRequest struct {
	URL                    string
	Name                   string
	Reader                 io.Reader
	PcrSlice               []string
	FunctionTokenPublicKey string
	AuthToken              string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

// Deploy encrypts the given function data within a secure enclave and stores the encrypted function for future use.
// Returns a function ID upon successful deployment. The stored function can only be decrypted within an enclave.
func Deploy(req DeployRequest) (string, []byte, error) {
	endpoint := fmt.Sprintf("%s/v1/deploy", req.URL)
	header := http.Header{"Sec-Websocket-Protocol": []string{"cape.runtime", req.AuthToken}}

	request, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	request.Header = header

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", nil, err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", nil, err
	}

	log.Infof("body: %+v", string(body))
	log.Infof("response: %+v", response)

	log.Info("Deploying function to Cape ...")

	conn, res, err := websocketDial(endpoint, req.Insecure, "cape.runtime", req.AuthToken)
	if err != nil {
		log.Error("error dialing websocket: ", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if res != nil {
			var e ErrorMsg
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				return "", nil, err
			}
			res.Body.Close()
			return "", nil, fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
		}
		return "", nil, err
	}
	defer conn.Close()

	p := getProtocol(conn)

	nonce, err := crypto.GetNonce()
	if err != nil {
		return "", nil, err
	}

	r := entities.StartRequest{Nonce: []byte(nonce), AuthToken: req.AuthToken}
	log.Debug("\n> Sending Nonce and Auth Token")
	if err := p.WriteStart(r); err != nil {
		log.Error("error writing deploy request")
		return "", nil, err
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Error("error reading attestation doc")
		return "", nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return "", nil, err
	}

	log.Debug("< Attestation document")
	doc, _, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Error("error attesting")
		return "", nil, err
	}

	hasher := sha256.New()
	// tReader is used to stream data to the hasher function.
	tReader := io.TeeReader(req.Reader, hasher)
	plaintext, err := io.ReadAll(tReader)
	if err != nil {
		log.Error("error reading plaintext function")
		return "", nil, err
	}

	// Print out the hash to the user.
	hash := hasher.Sum(nil)
	ciphertext, err := crypto.LocalEncrypt(*doc, plaintext)
	if err != nil {
		log.Error("error encrypting function")
		return "", nil, err
	}

	log.Debug("\n> Sending Public Key")
	if err := p.WriteFunctionPublicKey(req.FunctionTokenPublicKey); err != nil {
		log.Error("error sending public key")
		return "", nil, err
	}

	log.Debug("\n> Deploying Encrypted Function")
	err = writeFunction(conn, bytes.NewBuffer(ciphertext))
	if err != nil {
		return "", nil, err
	}

	log.Debug("* Waiting for deploy response...")

	resData, err := p.ReadDeploymentResults()
	if err != nil {
		return "", nil, err
	}
	log.Debugf("< Received Deploy Response %v", resData)

	return resData.ID, hash, nil
}

func writeFunction(conn *websocket.Conn, reader io.Reader) error {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		log.Errorf("error getting writer for function: %v", err)
		return err
	}
	defer writer.Close()

	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}

	return nil
}
