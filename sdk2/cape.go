package sdk2

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
)

type Client struct {
	URL          string
	FunctionAuth entities.FunctionAuth
	PCRs         []string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

type FuncConnection struct {
	Attestation *attest.AttestationDoc
	Conn        *websocket.Conn
	UserData    *attest.AttestationUserData
}

func (c Client) Connect(function, checksum string) (FuncConnection, error) {
	f, err := c.ConnectWithoutVerification(function)
	if err != nil {
		return FuncConnection{}, err
	}

	// TODO: is it a smell if UserData is stored just for this? do we need a private helper for the two Connects?
	if len(checksum) > 0 {
		if f.UserData.FuncChecksum == nil {
			return FuncConnection{}, fmt.Errorf("did not receive checksum from enclave")
		}
		checksumBytes, err := hex.DecodeString(checksum)
		if err != nil {
			return FuncConnection{}, fmt.Errorf("invalid checksum provided")
		}
		if !reflect.DeepEqual(checksumBytes, f.UserData.FuncChecksum) {
			return FuncConnection{}, fmt.Errorf("returned checksum did not match provided, got: %x, want %x", f.UserData.FuncChecksum, checksum)
		}
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(c.PCRs), f.Attestation)
	if err != nil {
		log.Println("error verifying PCRs")
		return FuncConnection{}, err
	}

	return f, nil
}

func (c Client) ConnectWithoutVerification(function string) (FuncConnection, error) {
	functionID, err := GetFunctionID(function, c.URL, c.FunctionAuth.Token)
	if err != nil {
		return FuncConnection{}, err
	}

	endpoint := fmt.Sprintf("%s/v1/run/%s", c.URL, functionID)

	authProtocolType := "cape.runtime"
	if c.FunctionAuth.Type == entities.AuthenticationTypeFunctionToken {
		authProtocolType = "cape.function"
	}

	conn, err := doDial(endpoint, c.Insecure, authProtocolType, c.FunctionAuth.Token)
	if err != nil {
		return FuncConnection{}, fmt.Errorf("connection failed: %w", err)
	}

	nonce, err := crypto.GetNonce()
	if err != nil {
		return FuncConnection{}, fmt.Errorf("failed to retrieve nonce: %w", err)
	}

	p := getProtocolFn(conn)

	r := entities.StartRequest{Nonce: []byte(nonce)}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(r)
	if err != nil {
		return FuncConnection{}, fmt.Errorf("error writing run request: %v", err)
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Println("error reading attestation doc")
		return FuncConnection{}, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return FuncConnection{}, err
	}

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, userData, err := runAttestation(attestDoc, rootCert)
	if err != nil {
		log.Println("error attesting")
		return FuncConnection{}, err
	}

	return FuncConnection{Attestation: doc, Conn: conn, UserData: userData}, nil
}

func (f FuncConnection) Invoke(data []byte) ([]byte, error) {
	//return []byte("sample output"), nil
	// TODO update these error messages, maybe panic instead?
	if f.Attestation == nil {
		log.Error("missing attestation document, you may need to run cape.Connect()")
		return nil, errors.New("missing attestation document")
	}
	if f.Conn == nil {
		log.Error("missing websocket connection, you may need to run cape.Connect()")
		return nil, errors.New("no active connection")
	}

	encryptedData, err := localEncrypt(*f.Attestation, data)
	if err != nil {
		log.Println("error encrypting")
		return nil, err
	}

	log.Debug("\n> Sending Encrypted Inputs")
	err = writeData(f.Conn, encryptedData)
	if err != nil {
		return nil, err
	}

	log.Debug("* Waiting for function results...")

	resData, err := getProtocolFn(f.Conn).ReadRunResults()
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

func (f FuncConnection) Close() error {
	return nil
}

func (c Client) Run(function, checkSum string, data []byte) ([]byte, error) {
	f, err := c.Connect(function, checkSum)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.Invoke(data)
}

func (c Client) RunWithoutValidation(function string, data []byte) ([]byte, error) {
	f, err := c.ConnectWithoutVerification(function)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.Invoke(data)
}
