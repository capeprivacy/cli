package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
)

// listCmd represents the run command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all deployed functions",
	Long:  "List all deployed functions for your user.\n",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := list(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

type DeploymentName struct {
	ID   string
	Name string
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func list(cmd *cobra.Command, args []string) error {
	u := C.SupervisorHost
	insecure := C.Insecure

	if len(args) > 0 {
		return UserError{Msg: "list does not take any arguments", Err: fmt.Errorf("invalid number of input arguments")}
	}

	t, err := getAuthToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}
	err = doList(u, insecure, auth)
	if err != nil {
		return fmt.Errorf("error calling list endpoint: %w", err)
	}

	return nil
}

func doList(url string, insecure bool, auth entities.FunctionAuth) error { //nolint:gocognit
	endpoint := fmt.Sprintf("%s/v1/functions", url)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return err
	}

	var bearer = "Bearer " + auth.Token
	req.Header.Add("Authorization", bearer)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New("list failed")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.New("could not read response body")
	}

	var deploymentNames []DeploymentName
	err = json.Unmarshal(body, &deploymentNames)
	if err != nil {
		return errors.New("malformed body in response")
	}

	fmt.Printf("%v", deploymentNames)
	return nil
}
