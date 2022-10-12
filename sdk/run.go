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
	// Configure on Cape struct??
	URL          string
	FunctionAuth entities.FunctionAuth

	// Required for Run
	Function string
	Data     []byte

	// Optional validation
	// TODO: is it user-friendly to keep these up to date?
	FuncChecksum []byte
	KeyChecksum  []byte
	PcrSlice     []string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

// TODO: defaults!!! make most of the RR members optional
// TODO: make CLI version call through to a default Cape client
// Run loads the given function into a secure enclave and invokes it on the given data, then returns the result.
func Run(req RunRequest) ([]byte, error) {
	functionID, err := GetFunctionID(req.Function, req.URL, req.FunctionAuth.Token)
	if err != nil {
		return nil, err
	}

	conn, doc, err := connect(req.URL, functionID, req.FunctionAuth, req.FuncChecksum, req.KeyChecksum, req.PcrSlice, req.Insecure)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return invoke(doc, conn, req.Data)
}

func connect(url string, functionID string, auth entities.FunctionAuth, funcChecksum []byte, keyChecksum []byte, pcrSlice []string, insecure bool) (*websocket.Conn, *attest.AttestationDoc, error) {
	endpoint := fmt.Sprintf("%s/v1/run/%s", url, functionID)

	authProtocolType := "cape.runtime"
	if auth.Type == entities.AuthenticationTypeFunctionToken {
		authProtocolType = "cape.function"
	}

	conn, err := doDial(endpoint, insecure, authProtocolType, auth.Token)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, nil, err
	}

	p := getProtocol(conn)

	r := entities.StartRequest{Nonce: []byte(nonce)}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(r)
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

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(pcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return nil, nil, err
	}

	// Check optional checksums only if provided
	if len(funcChecksum) > 0 {
		if userData.FuncChecksum == nil {
			return nil, nil, fmt.Errorf("did not receive checksum from enclave")
		}
		if !reflect.DeepEqual(funcChecksum, userData.FuncChecksum) {
			return nil, nil, fmt.Errorf("returned checksum did not match provided, got: %x, want %x", userData.FuncChecksum, funcChecksum)
		}
	}
	if len(keyChecksum) > 0 {
		if userData.KeyChecksum == nil {
			return nil, nil, fmt.Errorf("did not receive key policy checksum from enclave")
		}
		if !reflect.DeepEqual(keyChecksum, userData.KeyChecksum) {
			return nil, nil, fmt.Errorf("returned key policy checksum did not match provided, got: %x, want %x", userData.KeyChecksum, keyChecksum)
		}
	}

	return conn, doc, nil
}

func invoke(doc *attest.AttestationDoc, conn *websocket.Conn, data []byte) ([]byte, error) {
	if doc == nil {
		log.Error("missing attestation document, you may need to run cape.Connect()")
		return nil, errors.New("missing attestation document")
	}
	if conn == nil {
		log.Error("missing wesocket connection, you may need to run cape.Connect()")
		return nil, errors.New("no active connection")
	}

	encryptedData, err := crypto.LocalEncrypt(*doc, data)
	if err != nil {
		log.Println("error encrypting")
		return nil, err
	}

	log.Debug("\n> Sending Encrypted Inputs")
	err = writeData(conn, encryptedData)
	if err != nil {
		return nil, err
	}

	log.Debug("* Waiting for function results...")

	resData, err := getProtocol(conn).ReadRunResults()
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
