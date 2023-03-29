package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
)

type ErrorMsg struct {
	ErrorMsg string `json:"error"`
}

func (e ErrorMsg) Error() string {
	return e.ErrorMsg
}

type ErrServerForList struct {
	statusCode int
	message    string
}

func (e ErrServerForList) Error() string {
	return fmt.Sprintf("expected 200, got server response code when listing functions %d: %s", e.statusCode, e.message)
}

var ErrUnauthorized = errors.New("unauthorized: authentication required")

// listCmd represents the list command
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

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.PersistentFlags().IntP("limit", "", 50, "Limit the number of functions returned.")
	listCmd.PersistentFlags().IntP("offset", "", 0, "Number of functions to skip before listing.")
}

func list(cmd *cobra.Command, args []string) error {
	u := C.EnclaveHost
	insecure := C.Insecure

	limit, err := cmd.Flags().GetInt("limit")
	if err != nil {
		return err
	}

	offset, err := cmd.Flags().GetInt("offset")
	if err != nil {
		return err
	}

	format, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	if len(args) > 0 {
		return UserError{Msg: "list does not take any arguments", Err: fmt.Errorf("invalid number of input arguments")}
	}

	t, err := authToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken, Token: t}
	err = doList(u, insecure, auth, limit, offset, format)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return err
		}
		return fmt.Errorf("list failed: %w", err)
	}

	return nil
}

func doList(url string, insecure bool, auth entities.FunctionAuth, limit int, offset int, format string) error { //nolint:gocognit
	endpoint := fmt.Sprintf("%s/v1/functions?limit=%d&offset=%d", url, limit, offset)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return err
	}

	var bearer = "Bearer " + auth.Token
	req.Header.Add("Authorization", bearer)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot complete http request: %s", err)
	}

	if res.StatusCode != 200 {
		var e ErrorMsg
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return ErrServerForList{statusCode: res.StatusCode}
		}
		res.Body.Close()

		if res.StatusCode == 401 {
			return ErrUnauthorized
		}

		return ErrServerForList{res.StatusCode, e.ErrorMsg}
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.New("could not read response body")
	}

	var deploymentNames []entities.Deployment
	err = json.Unmarshal(body, &deploymentNames)
	if err != nil {
		return errors.New("malformed body in response")
	}

	if len(deploymentNames) == 0 {
		fmt.Println("No functions deployed.")
		return nil
	}

	if f, ok := listFormatters[format]; ok {
		return f(deploymentNames)
	}

	return printTable(deploymentNames)
}

var listFormatters = map[string]func([]entities.Deployment) error{
	"plain": printTable,
	"json":  printJSON,
}

func printTable(deps []entities.Deployment) error {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"#", "Name", "ID", "Created At"})
	localTime, err := time.LoadLocation("Local")
	if err != nil {
		return err
	}

	for i, deployment := range deps {
		t.AppendRow([]interface{}{i, deployment.Name, deployment.ID, deployment.CreatedAt.In(localTime).Format("Jan 02 2006 15:04")})
	}
	t.SetStyle(table.StyleLight)
	t.Render()
	return nil
}

func printJSON(deps []entities.Deployment) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		Deps  []entities.Deployment `json:"deployments"`
		Count int                   `json:"count"`
	}{
		Deps:  deps,
		Count: len(deps),
	})
}
