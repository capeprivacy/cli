package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
)

// listCmd represents the run command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all deployed functions",
	Long:  "List all deployed function, for your user.\n",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := list(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func list(cmd *cobra.Command, args []string) error {
	u := C.SupervisorHost
	insecure := C.Insecure

	if len(args) > 0 {
		return UserError{Msg: "too many arguments", Err: fmt.Errorf("invalid number of input arguments")}
	}

	t, err := getAuthToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}
	err = doList(u, insecure, auth)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	return nil
}

func doList(url string, insecure bool, auth entities.FunctionAuth) error { //nolint:gocognit
	endpoint := fmt.Sprintf("%s/v1/list", url)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New("list failed")
	}

	// TODO print list here
	return nil
}
