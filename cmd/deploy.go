package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/briandowns/spinner"
	czip "github.com/capeprivacy/cli/zip"
	"github.com/capeprivacy/go-kit/id"
	"github.com/spf13/cobra"
)

type DeployRequest struct {
	Data  []byte `json:"data"`
	Name  string `json:"name"`
	Nonce string `json:"nonce"`
}

type DeployResponse struct {
	ID                  string `json:"id"`
	AttestationDocument string `json:"attestation_document"`
}

// runCmd represents the request command
var deployCmd = &cobra.Command{
	Use:   "deploy [directory]",
	Short: "deploy a function",
	Long: `Deploy a function to Cape. 

This will return an ID that can later be used to invoke the deployed function
with cape run (see cape run -h for details).
`,

	RunE: deploy,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("token", "t", "", "token to use")
	deployCmd.PersistentFlags().StringP("name", "n", "", "a name to give this function (default is the directory name)")
}

func deploy(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("you must specify a directory to upload")
	}

	u, err := cmd.Flags().GetString("url")
	if err != nil {
		return err
	}

	n, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}

	functionInput := args[0]
	name := functionInput
	if n != "" {
		name = n
	}

	file, err := os.Open(functionInput)
	if err != nil {
		return fmt.Errorf("unable to read function directory or file: %w", err)
	}

	st, err := file.Stat()
	if err != nil {
		return fmt.Errorf("unable to read function file or directory: %s", err)
	}
	isZip := false
	if st.IsDir() {
		_, err = file.Readdirnames(1)
		if err != nil {
			return fmt.Errorf("please pass in a non-empty directory: %w", err)
		}
	} else {
		// Check if file ends with ".zip" extension.
		fileExtension := filepath.Ext(functionInput)
		if fileExtension != ".zip" {
			return fmt.Errorf("expected argument %s to be a zip file or directory", functionInput)
		}
		isZip = true
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("something went wrong: %w", err)
	}

	buf := new(bytes.Buffer)

	if isZip {
		f, err := os.Open(functionInput)
		if err != nil {
			return fmt.Errorf("unable to read function file: %w", err)
		}
		nBytes, err := io.Copy(buf, f)
		if nBytes <= 0 {
			return fmt.Errorf("zip file provided is empty")
		}
		if err != nil {
			return fmt.Errorf("unable to read function file: %w", err)
		}
		err = f.Close()
		if err != nil {
			return fmt.Errorf("something went wrong: %w", err)
		}
	} else {
		zipRoot := filepath.Base(functionInput)
		w := zip.NewWriter(buf)

		err = filepath.Walk(functionInput, czip.Walker(w, zipRoot))
		if err != nil {
			return fmt.Errorf("zipping directory failed: %w", err)
		}

		// Explicitly close now so that the bytes are flushed and
		// available in buf.Bytes() below.
		err = w.Close()
		if err != nil {
			return fmt.Errorf("zipping directory failed: %w", err)
		}

	}

	enclave, err := doStart(u)
	if err != nil {
		return fmt.Errorf("unable to start enclave %w", err)
	}

	id, err := doDeploy(u, enclave.id, name, buf.Bytes())
	if err != nil {
		return fmt.Errorf("unable to deploy function %w", err)
	}

	fmt.Printf("Success! Deployed function to Cape\nFunction ID ➜ %s\n", id)
	return nil
}

func doDeploy(url string, id id.ID, name string, data []byte) (string, error) {
	reqData := DeployRequest{
		Name:  name,
		Data:  data,
		Nonce: getNonce(),
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/v1/deploy/%s", url, id)
	buffer := bytes.NewBuffer(body)

	req, err := http.NewRequest("POST", endpoint, buffer)
	if err != nil {
		return "", fmt.Errorf("unable to create request %s", err)
	}

	s := spinner.New(spinner.CharSets[26], 300*time.Millisecond)
	s.Prefix = "Deploying function to Cape "
	s.Start()

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed %s", err)
	}

	s.Stop()

	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("bad status code %d", res.StatusCode)
	}

	resData := DeployResponse{}

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&resData)
	if err != nil {
		return "", fmt.Errorf("unable to decode response %s", err)
	}

	return resData.ID, nil
}
