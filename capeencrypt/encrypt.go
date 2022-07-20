package capeencrypt

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type ErrorMsg struct {
	Error string `json:"error"`
}

type Message struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

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

func Encrypt(encryptReq entities.EncryptRequest, endpoint string, insecure bool) (*entities.EncryptResponse, error) {
	ws, resp, err := websocketDial(endpoint, insecure)
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
		AuthToken: encryptReq.AuthToken,
		Nonce:     nonce,
	}
	log.Debug("> Start Request")
	if err := ws.WriteJSON(startReq); err != nil {
		return nil, err
	}

	var attestation Message
	if err := ws.ReadJSON(&attestation); err != nil {
		return nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return nil, err
	}

	log.Debug("< Attestation document")
	doc, err := runAttestation(attestation.Message, rootCert)
	if err != nil {
		return nil, err
	}

	encData, err := localEncrypt(*doc, []byte(encryptReq.Data))
	if err != nil {
		return nil, err
	}

	log.Debug("> Encrypted Data")
	if err := ws.WriteMessage(websocket.BinaryMessage, encData); err != nil {
		return nil, err
	}

	log.Debug("< Encrypted Response")
	var res entities.EncryptResponse
	_, d, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(d, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
