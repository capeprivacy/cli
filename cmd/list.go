package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/capeprivacy/go-kit/id"
	"github.com/spf13/cobra"
)

type DeploymentName struct {
	ID   id.ID
	Name string
}

// runCmd represents the request command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list function names",
	Long:  "list all deployed function names",
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
		return fmt.Errorf("unable to list deployed function names %w", err)
	}

	for _, r := range results {
		fmt.Printf("Success! ID | Function Name \n %s | %s", r.ID, r.Name)
	}

	return nil
}

func doList(url string) ([]DeploymentName, error) {
	endpoint := fmt.Sprintf("%s/v1/list", url)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("got error when requesting the list endpoint %s", err)
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
