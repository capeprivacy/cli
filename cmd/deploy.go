package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	czip "github.com/capeprivacy/cli/zip"
	"github.com/spf13/cobra"
)

type DeployRequest struct {
	Data  []byte
	Nonce string
}

type DeployResponse struct {
	ID                  string `json:"id"`
	AttestationDocument string `json:"attestation_document"`
}

// runCmd represents the request command
var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "deploy a function",
	Run:   deploy,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("token", "t", "", "token to use")
}

func deploy(cmd *cobra.Command, args []string) {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		panic(err)
	}

	if len(args) != 1 {
		panic("expected two args, path to file containing the function and path to file containing input data")
	}

	functionDir := args[0]
	zipRoot := filepath.Base(functionDir)

	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	err = filepath.Walk(functionDir, czip.Walker(w, zipRoot))
	if err != nil {
		panic(err)
	}

	// explicitly close now so that the bytes are flushed and
	// available in buf.Bytes() below.
	err = w.Close()
	if err != nil {
		panic(err)
	}

	enclave, err := doStart(u)
	if err != nil {
		panic(fmt.Sprintf("unable to start enclave %s", err))
	}

	ciphertext, err := doLocalEncrypt(enclave.attestation, buf.Bytes())
	if err != nil {
		panic(fmt.Sprintf("unable to do local encrypt %s", err))
	}

	id, err := doDeploy(u, ciphertext)
	if err != nil {
		panic(fmt.Sprintf("unable to deploy function %s", err))
	}

	fmt.Printf("Successfully deployed function. Function ID: %s", id)
}

func doDeploy(url string, ciphertext []byte) (string, error) {
	reqData := DeployRequest{
		Nonce: getNonce(),
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url+"/v1/deploy", bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("unable to create request %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed %s", err)
	}

	if res.StatusCode != http.StatusAccepted {
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
