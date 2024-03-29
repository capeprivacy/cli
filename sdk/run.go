package sdk

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli"

	"github.com/capeprivacy/attest/attest"
	capeCrypto "github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
)

type RunRequest struct {
	URL          string
	FunctionID   string
	Data         []byte
	FuncChecksum []byte
	KeyChecksum  []byte
	PcrSlice     []string
	FunctionAuth entities.FunctionAuth

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

type attestationDoc struct {
	decoded *attest.AttestationDoc
	raw     []byte
}

// Run loads the given function into a secure enclave and invokes it on the given data, then returns the result.
func Run(req RunRequest) (*cli.RunResult, error) {
	conn, doc, err := connect(req.URL, req.FunctionID, req.FunctionAuth, req.FuncChecksum, req.KeyChecksum, req.PcrSlice, req.Insecure)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		conn.Close()
	}()
	return invoke(doc, conn, req.Data)
}

func connect(url string, functionID string, functionAuth entities.FunctionAuth, funcChecksum []byte, keyChecksum []byte, pcrSlice []string, insecure bool) (*websocket.Conn, *attestationDoc, error) {
	endpoint := fmt.Sprintf("%s/v1/run/%s", url, functionID)

	authProtocolType := "cape.runtime"
	auth := functionAuth

	conn, err := doDial(endpoint, insecure, authProtocolType, auth.Token)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := capeCrypto.GetNonce()
	if err != nil {
		return nil, nil, err
	}

	p := getProtocol(conn)

	r := entities.StartRequest{Nonce: nonce}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(r)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error writing run request")
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		return nil, nil, err
	}

	verifier := attest.NewVerifier()

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, err := verifier.Verify(attestDoc, nonce)
	if err != nil {
		log.Println("error attesting")
		return nil, nil, err
	}

	userData := &AttestationUserData{}
	err = json.Unmarshal(doc.UserData, userData)
	if err != nil {
		log.Println("error unmarshalling user data")
		return nil, nil, err
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(pcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return nil, nil, err
	}

	if userData.FuncChecksum == nil && len(funcChecksum) > 0 {
		return nil, nil, fmt.Errorf("did not receive checksum from enclave")
	}

	// If checksum as an optional parameter has not been specified by the user, then we don't check the value.
	if len(funcChecksum) > 0 && !reflect.DeepEqual(funcChecksum, userData.FuncChecksum) {
		return nil, nil, fmt.Errorf("returned checksum did not match provided, got: %x, want %x", userData.FuncChecksum, funcChecksum)
	}

	if userData.KeyChecksum == nil && len(keyChecksum) > 0 {
		return nil, nil, fmt.Errorf("did not receive key policy checksum from enclave")
	}

	if len(keyChecksum) > 0 && !reflect.DeepEqual(keyChecksum, userData.KeyChecksum) {
		return nil, nil, fmt.Errorf("returned key policy checksum did not match provided, got: %x, want %x", userData.KeyChecksum, keyChecksum)
	}

	return conn, &attestationDoc{
		decoded: doc,
		raw:     attestDoc,
	}, nil
}

func invoke(attestDoc *attestationDoc, conn *websocket.Conn, data []byte) (*cli.RunResult, error) {
	encryptedData, err := capeCrypto.LocalEncrypt(*attestDoc.decoded, data)
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
	resData.DecodedAttestationDocument = attestDoc.decoded
	resData.RawAttestationDocument = attestDoc.raw

	// TODO -- connect is already doing this
	var ud AttestationUserData
	if err := json.Unmarshal(attestDoc.decoded.UserData, &ud); err != nil {
		return nil, err
	}

	if ud.SignatureVerificationKey != nil {
		log.Debugf("* Verifying Function Results.")
		publicKey, err := x509.ParsePKCS1PublicKey(ud.SignatureVerificationKey)
		if err != nil {
			return nil, err
		}

		c := sha256.New()
		if err := json.NewEncoder(c).Encode(resData.Checksums); err != nil {
			return nil, err
		}

		if err := rsa.VerifyPSS(publicKey, crypto.SHA256, c.Sum(nil), resData.SignedChecksums, nil); err != nil {
			return nil, err
		}

		log.Debugf("* Function Results Verified")
	}

	return resData, nil
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
