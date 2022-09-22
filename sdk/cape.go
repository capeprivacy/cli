package sdk

import (
	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/entities"
	"github.com/gorilla/websocket"
)

// The Cape struct is used to manage a connection to a secure enclave, especially when used for multiple function invocations
type Cape struct {
	// Configuration variables to set up the connection
	URL          string
	FunctionAuth entities.FunctionAuth

	// Internal state used to persist the connection
	conn *websocket.Conn
	doc  *attest.AttestationDoc
}

func (c Cape) Run(connReq ConnectRequest, data []byte) ([]byte, error) {

	err := c.Connect(connReq)
	if err != nil {
		return nil, err
	}
	defer c.Disconnect()
	return invoke(c, data)
}

func (c Cape) Connect(req ConnectRequest) error {
	return connect(c, req)
}

func (c Cape) Disconnect() error {
	if c.conn != nil {
		err := c.conn.Close()
		if err != nil {
			return err
		}
	}
	c.conn = nil
	c.doc = nil

	return nil
}

func (c Cape) Invoke(data []byte) ([]byte, error) {
	return invoke(c, data)
}
