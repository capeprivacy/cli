package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/go-kit/id"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// runCmd represents the request command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run a deployed function with data",
	Long:  "run a deployed function with data, takes function id and path to data",
	Run:   run,
}

type RunRequest struct {
	FunctionID string `json:"function_id"`
	Input      string `json:"input"`

	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce string `json:"nonce"`
}

type RunResponse struct {
	Attestation Outputs `json:"attestation"`
	Results     Outputs `json:"results"`
}

type ErrorRunResponse struct {
	Message string `json:"message"`
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.PersistentFlags().StringP("token", "t", "", "token to use")
}

func run(cmd *cobra.Command, args []string) {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Errorf("flag not found: %s", err)
	}

	if len(args) != 2 {
		log.Error("Error, invalid arguments")
		_ = cmd.Help()
		return
	}

	functionID := args[0]
	dataFile := args[1]

	inputData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		log.Errorf("unable to read data file: %s", err)
	}

	fmt.Println("> Starting enclave ...")
	enclave, err := doStart(u)
	if err != nil {
		log.Errorf("unable to start enclave: %s", err)
		return
	}

	fmt.Println("> Enclave started")
	fmt.Println("> Encrypting input data ...")

	encryptedData, err := crypto.LocalEncrypt(enclave.attestation, inputData)
	if err != nil {
		log.Errorf("unable to encrypt data %s", err)
		return
	}

	fmt.Println("> Processing ...")
	results, err := doRun(u, enclave.id, functionID, encryptedData)
	if err != nil {
		log.Errorf("> error processing data: %s", err)
		return
	}

	data, err := base64.StdEncoding.DecodeString(results.Data)
	if err != nil {
		log.Errorf("> could not decode results.data: %v", err)
		return
	}

	stdout, err := base64.StdEncoding.DecodeString(results.Stdout)
	if err != nil {
		log.Errorf("> could not decode stdout: %v", err)
		return
	}

	stderr, err := base64.StdEncoding.DecodeString(results.Stderr)
	if err != nil {
		log.Errorf("> could not decode stderr: %v", err)
		return
	}

	fmt.Printf("Success!\nData:\t%s\nStdout:\t%s\nStderr:\t%s\nExit Code:\t%s\n", data, stdout, stderr, results.ExitStatus)
}

func doRun(url string, id id.ID, functionID string, encryptedData []byte) (*Outputs, error) {
	inputDataStr := base64.StdEncoding.EncodeToString(encryptedData)

	runReq := &RunRequest{
		FunctionID: functionID,
		Input:      inputDataStr,
		Nonce:      getNonce(),
	}

	body, err := json.Marshal(runReq)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/v1/run/%s", url, id)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code %d", res.StatusCode)
	}

	resData := &RunResponse{}
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(resData)
	if err != nil {
		return nil, err
	}

	return &resData.Results, nil
}
