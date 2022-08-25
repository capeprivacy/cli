package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/protocol"
)

// deleteCmd represents the run command
var deleteCmd = &cobra.Command{
	Use:   "delete function_id",
	Short: "Delete a deployed function",
	Long:  "Delete a deployed function, takes function id.\n",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := delete(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

type DeleteResponse struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

type ErrorDeleteResponse struct {
	Message string `json:"message"`
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}

func delete(cmd *cobra.Command, args []string) error {
	u := C.EnclaveHost
	insecure := C.Insecure

	if len(args) != 1 {
		return UserError{Msg: "you must pass a function ID", Err: fmt.Errorf("invalid number of input arguments")}
	}

	functionID := args[0]

	t, err := getAuthToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}
	err = doDelete(u, functionID, insecure, auth)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	return nil
}

func doDelete(url string, functionID string, insecure bool, auth entities.FunctionAuth) error { //nolint:gocognit
	endpoint := fmt.Sprintf("%s/v1/delete/%s", url, functionID)

	authProtocolType := "cape.runtime"
	c, res, err := websocketDial(endpoint, insecure, authProtocolType, auth.Token)
	if err != nil {
		log.Error("error dialing websocket: ", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if res != nil {
			var e ErrorMsg
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				return err
			}
			res.Body.Close()
			return fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
		}
		return err
	}
	defer c.Close()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return err
	}

	p := protocol.Protocol{Websocket: c}

	req := entities.StartRequest{Nonce: []byte(nonce), AuthToken: auth.Token}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(req)
	if err != nil {
		return errors.Wrap(err, "error writing delete request")
	}

	resData, err := p.ReadDeleteResults()
	if err != nil {
		return err
	}
	log.Debugf("< Received Delete Results.")
	if !resData.Done {
		return fmt.Errorf("delete failed with error")
	}

	return nil
}
