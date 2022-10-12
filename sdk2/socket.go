package sdk2

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	proto "github.com/capeprivacy/cli/protocol"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
)

type ErrorMsg struct {
	Error string `json:"error"`
}

type protocol interface {
	WriteStart(request entities.StartRequest) error
	ReadAttestationDoc() ([]byte, error)
	ReadRunResults() (*entities.RunResults, error)
	WriteBinary([]byte) error
	WriteFunctionInfo(key string, name string) error
	ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error)
}

func getProtocol(ws *websocket.Conn) protocol {
	return proto.Protocol{Websocket: ws}
}

func websocketDial(urlStr string, insecure bool, authProtocolType string, authToken string) (*websocket.Conn, *http.Response, error) {
	u, err := transformURL(urlStr)
	if err != nil {
		log.Error("error transforming URL: ", err)
		return nil, nil, err
	}

	if insecure {
		// TODO: don't edit the default dialer
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

func customError(res *http.Response) error {
	var e ErrorMsg
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		return err
	}
	res.Body.Close()
	return fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
}

func doDial(endpoint string, insecure bool, authProtocolType string, authToken string) (*websocket.Conn, error) {
	log.Debug("Connecting ...")
	conn, res, err := websocketDial(endpoint, insecure, authProtocolType, authToken)
	if err == nil {
		return conn, nil
	}

	if res == nil {
		return nil, err
	}

	if res.StatusCode != 307 {
		return nil, customError(res)
	}

	log.Debug("* Received 307 redirect")

	location, err := res.Location()
	if err != nil {
		log.Error("could not get location off header")
		return nil, err
	}

	conn, res, err = websocketDial(location.String(), insecure, authProtocolType, authToken)
	if err != nil {
		if res != nil {
			customErr := customError(res)
			res.Body.Close()
			return nil, customErr
		}
		log.Error("could not dial websocket again after 307 redirect")
		return nil, err
	}

	return conn, nil
}

var getProtocolFn = getProtocol
var runAttestation = attest.Attest
var localEncrypt = crypto.LocalEncrypt
