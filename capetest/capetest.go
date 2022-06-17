package capetest

import (
	"crypto/tls"
	"net/http"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/gorilla/websocket"
)

type TestRequest struct {
	Function []byte
	Input    []byte
}

type StartRequest struct {
	Nonce     []byte `json:"nonce"`
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

	return websocket.DefaultDialer.Dial(url, nil)
}

func CapeTest(testReq TestRequest, endpoint string, insecure bool) (*RunResults, error) {
	conn, _, err := websocketDial(endpoint, insecure)
	if err != nil {
		return nil, err
	}

	startReq := StartRequest{}
	if err := conn.WriteJSON(startReq); err != nil {
		return nil, err
	}

	var attestation Message
	if err := conn.ReadJSON(&attestation); err != nil {
		return nil, err
	}

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

	if err := conn.WriteMessage(websocket.BinaryMessage, encFn); err != nil {
		return nil, err
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, encInput); err != nil {
		return nil, err
	}

	var res RunResults
	if err := conn.ReadJSON(&res); err != nil {
		return nil, err
	}

	return &res, nil
}

var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
