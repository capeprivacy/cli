package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
)

// deleteCmd represents the delete command
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

func init() {
	rootCmd.AddCommand(deleteCmd)

	deleteCmd.PersistentFlags().StringP("token", "t", "", "authorization token to use")
}

func delete(cmd *cobra.Command, args []string) error {
	u := C.EnclaveHost
	insecure := C.Insecure

	if len(args) != 1 {
		return UserError{Msg: "you must pass a function ID", Err: fmt.Errorf("invalid number of input arguments")}
	}

	functionID := args[0]

	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		t, err := authToken()
		if err != nil {
			return err
		}

		token = t
	}

	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken, Token: token}
	err := doDelete(u, functionID, insecure, auth)
	if err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}

	return nil
}

func doDelete(url string, functionID string, insecure bool, auth entities.FunctionAuth) error { //nolint:gocognit
	endpoint := fmt.Sprintf("%s/v1/functions/%s", url, functionID)

	req, err := http.NewRequest("DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("cannot create http request: %s", err)
	}

	var bearer = "Bearer " + auth.Token
	req.Header.Add("Authorization", bearer)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot complete http request: %s", err)
	}

	if res.StatusCode != 200 {
		if res.StatusCode == 404 {
			return fmt.Errorf("function ID not found: %s", functionID)
		}

		var errMsg ErrorMsg
		if err := json.NewDecoder(res.Body).Decode(&errMsg); err != nil {
			return fmt.Errorf("expected 200, got server response code %d and could not decode err msg", res.StatusCode)
		}

		if errMsg.Error() != "" {
			return errMsg
		}

		return fmt.Errorf("expected 200, got server response code %d", res.StatusCode)
	}

	log.Infof("Success! Function %s deleted.\n", functionID)

	return nil
}
