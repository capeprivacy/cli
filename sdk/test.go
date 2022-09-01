package sdk

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/entities"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
)

type TestRequest struct {
	Function  []byte
	Input     []byte
	AuthToken string

	// For development use only: circumvents some token authorization when true
	Insecure bool
}

type ErrorMsg struct {
	Error string `json:"error"`
}

// Test simulates the workflow of Deploy and Run, without storing the function.
// It loads the given function into an enclave, runs it on the given data, and returns the result.
// Use Test to verify that your function will work before storing it via Deploy.
func Test(testReq TestRequest, endpoint string) (*entities.RunResults, error) {
	conn, resp, err := websocketDial(endpoint, testReq.Insecure, "cape.runtime", testReq.AuthToken)
	if err != nil {
		log.Error("error dialing websocket", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if resp != nil {
			var e ErrorMsg
			if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
				return nil, err
			}
			resp.Body.Close()
			return nil, fmt.Errorf("error code: %d, reason: %s", resp.StatusCode, e.Error)
		}
		return nil, err
	}
	defer conn.Close()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, err
	}

	p := getProtocolFn(conn)

	startReq := entities.StartRequest{
		AuthToken: testReq.AuthToken,
		Nonce:     []byte(nonce),
	}
	log.Debug("> Start Request")
	if err := p.WriteStart(startReq); err != nil {
		return nil, err
	}

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		return nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return nil, err
	}

	log.Debug("< Attestation document")
	doc, _, err := runAttestation(attestDoc, rootCert)
	if err != nil {
		return nil, err
	}

	encFn, err := localEncrypt(*doc, testReq.Function)
	if err != nil {
		return nil, err
	}

	encInput, err := localEncrypt(*doc, testReq.Input)
	if err != nil {
		return nil, err
	}

	log.Debug("> Encrypted function")
	if err := p.WriteBinary(encFn); err != nil {
		return nil, err
	}

	log.Debug("> Encrypted input")
	if err := p.WriteBinary(encInput); err != nil {
		return nil, err
	}

	res, err := p.ReadRunResults()
	if err != nil {
		return nil, err
	}
	log.Debug("< Test Response", res)

	return res, nil
}

func websocketDial(urlStr string, insecure bool, authProtocolType string, authToken string) (*websocket.Conn, *http.Response, error) {
	u, err := transformURL(urlStr)
	if err != nil {
		log.Error("error transforming URL", err)
		return nil, nil, err
	}

	if insecure {
		websocket.DefaultDialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	str := fmt.Sprintf("* Dialing %s", u)
	if insecure {
		str += " (insecure)"
	}

	secWebsocketProtocol := http.Header{"Sec-Websocket-Protocol": []string{authProtocolType, authToken}}

	log.Debug(str)

	c, r, err := websocket.DefaultDialer.Dial(u, secWebsocketProtocol)
	if err != nil {
		return nil, r, err
	}

	log.Debugf("* Websocket connection established")
	return c, r, nil
}

func transformURL(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else if u.Scheme == "https" {
		u.Scheme = "wss"
	}

	return u.String(), nil
}

var getProtocolFn = getProtocol
var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
