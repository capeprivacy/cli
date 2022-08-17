package capetest

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	sentinelEntities "github.com/capeprivacy/sentinel/entities"
	"github.com/capeprivacy/sentinel/runner"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
)

type TestRequest struct {
	Function  []byte
	Input     []byte
	AuthToken string
}

// TODO -- cmd package also defines this
type ErrorMsg struct {
	Error string `json:"error"`
}

// TODO -- cmd package also defines this
func websocketDial(url string, insecure bool, authToken string) (*websocket.Conn, *http.Response, error) {
	if insecure {
		websocket.DefaultDialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	str := fmt.Sprintf("* Dialing %s", url)
	if insecure {
		str += " (insecure)"
	}

	secWebsocketProtocol := http.Header{"Sec-Websocket-Protocol": []string{"auth", authToken}}

	log.Debug(str)
	c, r, err := websocket.DefaultDialer.Dial(url, secWebsocketProtocol)
	if err != nil {
		return nil, r, err
	}

	log.Debugf("* Websocket connection established")
	return c, r, nil
}

type Protocol interface {
	WriteStart(request sentinelEntities.StartRequest) error
	ReadAttestationDoc() ([]byte, error)
	ReadRunResults() (*sentinelEntities.RunResults, error)
	WriteBinary([]byte) error
}

func protocol(ws *websocket.Conn) Protocol {
	return runner.Protocol{Websocket: ws}
}

var getProtocol = protocol

func CapeTest(testReq TestRequest, endpoint string, insecure bool) (*sentinelEntities.RunResults, error) {
	conn, resp, err := websocketDial(endpoint, insecure, testReq.AuthToken)
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

	p := getProtocol(conn)

	startReq := sentinelEntities.StartRequest{
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

var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
