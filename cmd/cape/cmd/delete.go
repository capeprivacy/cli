package cmd

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
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

func init() {
	rootCmd.AddCommand(deleteCmd)
}

func delete(cmd *cobra.Command, args []string) error {
	u := C.SupervisorHost
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot complete http request: %s", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("server response code %d", resp.StatusCode)
	}

	log.Infof("Success! Function %s deleted.\n", functionID)

	return nil
}
