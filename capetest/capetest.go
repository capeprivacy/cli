package capetest

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/capeprivacy/cli/entities"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
)

type TestRequest struct {
	Function  []byte
	Input     []byte
	AuthToken string
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
	conn, resp, err := websocketDial(endpoint, insecure)
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

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, err
	}

	startReq := entities.StartRequest{
		AuthToken: testReq.AuthToken,
		Nonce:     nonce,
	}
	log.Debug("> Start Request")
	if err := conn.WriteJSON(startReq); err != nil {
		return nil, err
	}

	var attestation Message
	if err := conn.ReadJSON(&attestation); err != nil {
		return nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return nil, err
	}

	log.Debug("< Attestation document")
	doc, _, err := runAttestation(attestation.Message, rootCert)
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
	log.Debug("< Test Response", res)

	return &res, nil
}

var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
