package sdk

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/attest/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
	proto "github.com/capeprivacy/cli/protocol"
)

type protocol interface {
	WriteStart(request entities.StartRequest) error
	ReadAttestationDoc() ([]byte, error)
	ReadRunResults() (*entities.RunResults, error)
	WriteBinary([]byte) error
	WriteFunctionInfo(name string) error
	ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error)
}

func getProtocol(ws *websocket.Conn) protocol {
	return proto.Protocol{Websocket: ws}
}

type DeployRequest struct {
	URL       string
	Name      string
	Reader    io.Reader
	PcrSlice  []string
	AuthToken string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

// Deploy encrypts the given function data within a secure enclave and stores the encrypted function for future use.
// Returns a function ID upon successful deployment. The stored function can only be decrypted within an enclave.
func Deploy(req DeployRequest, keyReq KeyRequest) (string, []byte, error) {
	endpoint := fmt.Sprintf("%s/v1/deploy", req.URL)
	log.Info("Deploying function to Cape ...")

	conn, err := doDial(endpoint, req.Insecure, "cape.runtime", req.AuthToken)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		conn.Close()
	}()

	p := getProtocol(conn)

	nonce, err := crypto.GetNonce()
	if err != nil {
		return "", nil, err
	}

	r := entities.StartRequest{Nonce: nonce}
	log.Debug("\n> Sending Nonce and Auth Token")
	if err := p.WriteStart(r); err != nil {
		log.Error("error writing deploy request")
		return "", nil, err
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		return "", nil, err
	}

	verifier := attest.NewVerifier()

	log.Debug("< Attestation document")
	doc, err := verifier.Verify(attestDoc, nonce)
	if err != nil {
		log.Error("error attesting")
		return "", nil, err
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(req.PcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
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

	ciphertext, err := EncryptBytes(keyReq, plaintext)
	if err != nil {
		log.Error("error encrypting function")
		return "", nil, err
	}

	log.Debug("\n> Sending Public Key")
	if err := p.WriteFunctionInfo(req.Name); err != nil {
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
	log.Debugf("< Received Deploy Response: ID: %s", resData.ID)

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
