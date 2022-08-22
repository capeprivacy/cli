package sdk

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
)

type RunRequest struct {
	URL           string
	FunctionID    string
	Data          []byte
	Insecure      bool
	FuncHash      []byte
	KeyPolicyHash []byte
	PcrSlice      []string
	AuthToken     string
	FunctionToken string
}

func Run(req RunRequest) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/v1/run/%s", req.URL, req.FunctionID)

	c, res, err := WebsocketDial(endpoint, req.Insecure, req.AuthToken)
	if err != nil {
		log.Error("error dialing websocket: ", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if res != nil {
			var e ErrorMsg
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				return nil, err
			}
			res.Body.Close()
			return nil, fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
		}
		return nil, err
	}
	defer c.Close()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, err
	}

	p := GetProtocol(c)

	r := entities.StartRequest{Nonce: []byte(nonce), AuthToken: req.AuthToken}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(r)
	if err != nil {
		return nil, errors.Wrap(err, "error writing run request")
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Println("error reading attestation doc")
		return nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return nil, err
	}

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, userData, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Println("error attesting")
		return nil, err
	}

	if userData.FuncHash == nil && len(req.FuncHash) > 0 {
		return nil, fmt.Errorf("did not receive function hash from enclave")
	}

	// If function hash as an optional parameter has not been specified by the user, then we don't check the value.
	if len(req.FuncHash) > 0 && !reflect.DeepEqual(req.FuncHash, userData.FuncHash) {
		return nil, fmt.Errorf("returned function hash did not match provided, got: %x, want %x", userData.FuncHash, req.FuncHash)
	}

	if userData.KeyPolicyHash == nil && len(req.KeyPolicyHash) > 0 {
		return nil, fmt.Errorf("did not receive key policy hash from enclave")
	}

	if len(req.KeyPolicyHash) > 0 && !reflect.DeepEqual(req.KeyPolicyHash, userData.KeyPolicyHash) {
		return nil, fmt.Errorf("returned key policy hash did not match provided, got: %x, want %x", userData.KeyPolicyHash, req.KeyPolicyHash)
	}

	encryptedData, err := crypto.LocalEncrypt(*doc, req.Data)
	if err != nil {
		log.Println("error encrypting")
		return nil, err
	}

	log.Debug("\n> Sending Encrypted Inputs")
	err = writeData(c, encryptedData)
	if err != nil {
		return nil, err
	}

	log.Debug("* Waiting for function results...")

	resData, err := p.ReadRunResults()
	if err != nil {
		return nil, err
	}
	log.Debugf("< Received Function Results.")

	return resData.Message, nil
}

func writeData(conn *websocket.Conn, data []byte) error {
	w, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = w.Write(data)
	if err != nil {
		return err
	}

	return nil
}
