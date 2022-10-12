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

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool

	// Internal state used to persist the connection
	conn *websocket.Conn
	doc  *attest.AttestationDoc
}

// TODO: TEST support for function name
// TODO: should Connect create and return the client instead of requiring user to create client?
func (c Cape) Connect(function string, funcChecksum []byte, keyChecksum []byte, pcrSlice []string) error {
	functionID, err := GetFunctionID(function, c.URL, c.FunctionAuth.Token)
	if err != nil {
		return err
	}

	conn, doc, err := connect(c.URL, functionID, c.FunctionAuth, funcChecksum, keyChecksum, pcrSlice, c.Insecure)
	if err != nil {
		return err
	}
	c.conn, c.doc = conn, doc
	return nil
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
	return invoke(c.doc, c.conn, data)
}
