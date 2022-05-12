package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

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

	if len(args) != 2 {
		panic("expected two arguments, name of function and path to a directory to zip")
	}

	name := args[0]
	functionDir := args[1]

	file, err := os.Open(functionDir)
	if err != nil {
		panic(err)
	}

	st, err := file.Stat()
	if err != nil {
		panic(err)
	}

	if !st.IsDir() {
		panic(fmt.Sprintf("expected argument %s to be a directory", functionDir))
	}

	err = file.Close()
	if err != nil {
		panic(err)
	}

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

	id, err := doDeploy(u, enclave.id, name, buf.Bytes())
	if err != nil {
		panic(fmt.Sprintf("unable to deploy function %s", err))
	}

	fmt.Printf("Successfully deployed function. Function ID: %s", id)
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
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("unable to create request %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed %s", err)
	}

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