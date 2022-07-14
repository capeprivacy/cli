package capetest

import (
	"crypto/tls"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/websocket"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
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
type ErrorMsg struct {
	Error string `json:"error"`
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
	conn, resp, err := websocketDial(endpoint, insecure)
	if err != nil {
		log.Error("error dialing websocket", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if resp != nil {
			defer resp.Body.Close()
			var e ErrorMsg
			if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
				return nil, err
			}
			log.Errorf("error code: %d, reason: %s", resp.StatusCode, e.Error)
		}
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
