package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/capeprivacy/go-kit/id"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

type DeploymentName struct {
	ID   id.ID
	Name string
}

// listCmd represents the request command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list deployed functions",
	Long:  "list all deployed functions (ID and function name)",
	RunE:  list,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func list(cmd *cobra.Command, args []string) error {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		return err
	}

	results, err := doList(u)
	if err != nil {
		return fmt.Errorf("unable to list deployed functions %w", err)
	}

	t := table.NewWriter()
	t.SetOutputMirror(cmd.OutOrStdout())
	t.AppendHeader([]interface{}{"deployment_id", "function_name"})

	for _, r := range results {
		t.AppendRow(table.Row{r.ID, r.Name})
	}

	t.Render()

	return nil
}

func doList(url string) ([]DeploymentName, error) {
	endpoint := path.Join(url, "/v1/list")

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create list request %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list request failed %s", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code %d", res.StatusCode)
	}

	results := []DeploymentName{}

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&results)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response %s", err)
	}

	return results, nil
}
