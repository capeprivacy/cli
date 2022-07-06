package capetest

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type TestRequest struct {
	Function  []byte
	Input     []byte
	AuthToken string
}

type StartRequest struct {
	Nonce     string `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type RunResults struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

type Message struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

// TODO -- cmd package also defines this
func websocketDial(url string, insecure bool) (*websocket.Conn, *http.Response, error) {
	if insecure {
		websocket.DefaultDialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	str := fmt.Sprintf("* Dialing %s", url)
	if insecure {
		str += " (insecure)"
	}

	log.Debug(str)
	c, r, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("* Websocket connection established")
	return c, r, nil
}

func CapeTest(testReq TestRequest, endpoint string, insecure bool) (*RunResults, error) {
	conn, _, err := websocketDial(endpoint, insecure)
	if err != nil {
		return nil, err
	}

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, err
	}

	startReq := StartRequest{
		AuthToken: testReq.AuthToken,
		Nonce:     nonce,
	}
	log.Debugf("> Start Request: %v", startReq)
	if err := conn.WriteJSON(startReq); err != nil {
		return nil, err
	}

	var attestation Message
	if err := conn.ReadJSON(&attestation); err != nil {
		return nil, err
	}

	log.Debug("< Attestation document")
	doc, err := runAttestation(attestation.Message)
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
	if err := conn.WriteMessage(websocket.BinaryMessage, encFn); err != nil {
		return nil, err
	}

	log.Debug("> Encrypted input")
	if err := conn.WriteMessage(websocket.BinaryMessage, encInput); err != nil {
		return nil, err
	}

	var res RunResults
	if err := conn.ReadJSON(&res); err != nil {
		return nil, err
	}
	log.Debug("< Test Response: %v", res)

	return &res, nil
}

var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
