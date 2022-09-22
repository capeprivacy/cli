package sdk

import (
	"fmt"
	"reflect"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
)

type RunRequest struct {
	ConnectRequest

	URL          string
	Data         []byte
	FunctionAuth entities.FunctionAuth
}

type ConnectRequest struct {
	FunctionID   string
	FuncChecksum []byte
	KeyChecksum  []byte
	PcrSlice     []string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

// Run loads the given function into a secure enclave and invokes it on the given data, then returns the result.
func Run(req RunRequest) ([]byte, error) {
	cape := Cape{
		URL:          req.URL,
		FunctionAuth: req.FunctionAuth,
	}
	err := connect(cape, req.ConnectRequest)
	if err != nil {
		return nil, err
	}
	defer cape.Disconnect()
	return invoke(cape, req.Data)
}

func connect(cape Cape, req ConnectRequest) error {
	endpoint := fmt.Sprintf("%s/v1/run/%s", cape.URL, req.FunctionID)

	authProtocolType := "cape.runtime"
	auth := cape.FunctionAuth
	if auth.Type == entities.AuthenticationTypeFunctionToken {
		authProtocolType = "cape.function"
	}

	conn, err := doDial(endpoint, req.Insecure, authProtocolType, auth.Token)
	if err != nil {
		return err
	}

	nonce, err := crypto.GetNonce()
	if err != nil {
		return err
	}

	p := getProtocol(conn)

	r := entities.StartRequest{Nonce: []byte(nonce)}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(r)
	if err != nil {
		return errors.Wrap(err, "error writing run request")
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Println("error reading attestation doc")
		return err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return err
	}

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, userData, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Println("error attesting")
		return err
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(req.PcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return err
	}

	if userData.FuncChecksum == nil && len(req.FuncChecksum) > 0 {
		return fmt.Errorf("did not receive checksum from enclave")
	}

	// If checksum as an optional parameter has not been specified by the user, then we don't check the value.
	if len(req.FuncChecksum) > 0 && !reflect.DeepEqual(req.FuncChecksum, userData.FuncChecksum) {
		return fmt.Errorf("returned checksum did not match provided, got: %x, want %x", userData.FuncChecksum, req.FuncChecksum)
	}

	if userData.KeyChecksum == nil && len(req.KeyChecksum) > 0 {
		return fmt.Errorf("did not receive key policy checksum from enclave")
	}

	if len(req.KeyChecksum) > 0 && !reflect.DeepEqual(req.KeyChecksum, userData.KeyChecksum) {
		return fmt.Errorf("returned key policy checksum did not match provided, got: %x, want %x", userData.KeyChecksum, req.KeyChecksum)
	}

	cape.conn = conn
	cape.doc = doc

	return nil
}

func invoke(cape Cape, data []byte) ([]byte, error) {
	if cape.doc == nil {
		log.Error("missing attestation document, you may need to run cape.Connect()")
		return nil, errors.New("missing attestation document")
	}
	if cape.conn == nil {
		log.Error("missing wesocket connection, you may need to run cape.Connect()")
		return nil, errors.New("no active connection")
	}

	encryptedData, err := crypto.LocalEncrypt(*cape.doc, data)
	if err != nil {
		log.Println("error encrypting")
		return nil, err
	}

	log.Debug("\n> Sending Encrypted Inputs")
	err = writeData(cape.conn, encryptedData)
	if err != nil {
		return nil, err
	}

	log.Debug("* Waiting for function results...")

	resData, err := getProtocol(cape.conn).ReadRunResults()
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
