package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/go-kit/id"
	"github.com/spf13/cobra"
)

// runCmd represents the request command
var runCmd = &cobra.Command{
	Use:   "run [function id] [input data]",
	Short: "run a deployed function with data",
	Long:  "run a deployed function with data, takes function id and path to data",
	RunE:  run,
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

func run(cmd *cobra.Command, args []string) error {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		return fmt.Errorf("flag not found: %w", err)
	}

	if len(args) != 2 {
		return fmt.Errorf("you must pass a function ID and input data")
	}

	functionID := args[0]
	dataFile := args[1]

	inputData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		return fmt.Errorf("unable to read data file: %w", err)
	}

	enclave, err := doStart(u)
	if err != nil {
		return fmt.Errorf("unable to start enclave: %w", err)
	}

	encryptedData, err := crypto.LocalEncrypt(enclave.attestation, inputData)
	if err != nil {
		return fmt.Errorf("unable to encrypt data %w", err)
	}

	s := spinner.New(spinner.CharSets[26], 300*time.Millisecond)
	s.Prefix = fmt.Sprintf("Running function %s with data %s ", functionID, dataFile)
	s.Writer = os.Stderr
	s.Start()

	results, err := doRun(u, enclave.id, functionID, encryptedData)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	s.Stop()

	data, err := base64.StdEncoding.DecodeString(results.Data)
	if err != nil {
		return fmt.Errorf("could not decode results.data: %w", err)
	}

	stdout, err := base64.StdEncoding.DecodeString(results.Stdout)
	if err != nil {
		return fmt.Errorf("could not decode stdout: %w", err)
	}

	stderr, err := base64.StdEncoding.DecodeString(results.Stderr)
	if err != nil {
		return fmt.Errorf("could not decode stderr: %w", err)
	}

	if results.ExitStatus != "0" {
		fmt.Fprintf(os.Stderr, "error!\nStdout:\t%s\nStderr:\t%s\nExit Code:\t%s\n", stdout, stderr, results.ExitStatus)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Success! Results from your function\n\tStdout:\t%s\n\tStderr:\t%s\n\tExit Code:\t%s\n", stdout, stderr, results.ExitStatus)
	fmt.Println(string(data))
	return nil
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
