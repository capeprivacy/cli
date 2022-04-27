package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/go-kit/id"
	"github.com/spf13/cobra"
)

type BeginResponse struct {
	ID                  id.ID     `json:"id"`
	AttestationDocument string    `json:"attestation_document"`
	CreatedAt           time.Time `json:"created_at"`
}

type RunRequest struct {
	Function string `json:"function"`
	Input    string `json:"input"`
}

type RunResponse struct {
	AttestationDocument string `json:"attestation_document"`
	Results             string `json:"results"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type enclave struct {
	id          id.ID
	attestation attest.AttestationDoc
}

// runCmd represents the request command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "runs function or data",
	Run:   run,
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.PersistentFlags().StringP("token", "t", "", "token to use")
}

func run(cmd *cobra.Command, args []string) {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		panic(err)
	}

	if len(args) != 2 {
		panic("expected four args, path to file containing the function, secret for that data, path to file containing input data and secret for that data")
	}

	functionFile := args[0]
	dataFile := args[1]

	functionData, err := ioutil.ReadFile(functionFile)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	inputData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	enclave, err := doBegin(u)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	encryptedData := EncryptedData{}
	err = json.Unmarshal(functionData, &encryptedData)
	if err == nil {
		results, err := handleDataEncrypted(u, enclave, functionData, inputData)
		if err != nil {
			panic(fmt.Sprintf("unable to handle encrypted data %s", err))
		}

		fmt.Printf("Successfully ran function. Your results are '%s'\n", results)
		return
	}

	results, err := handleDataNotEncrypted(u, enclave, functionData, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to handle not already encrypted data %s", err))
	}

	fmt.Printf("Successfully ran function. Your results are '%s'\n", results)
}

func handleDataEncrypted(URL string, enclave *enclave, functionData []byte, inputData []byte) (string, error) {
	encryptedFunc := EncryptedData{}
	err := json.Unmarshal(functionData, &encryptedFunc)
	if err != nil {
		return "", err
	}

	encryptedInput := EncryptedData{}
	err = json.Unmarshal(inputData, &encryptedInput)
	if err != nil {
		return "", err
	}

	functionData = append(encryptedFunc.Secret, encryptedFunc.Data...)
	encryptedFunctionData, err := doLocalEncrypt(enclave.attestation, functionData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	inputData = append(encryptedInput.Secret, encryptedInput.Data...)
	encryptedInputData, err := doLocalEncrypt(enclave.attestation, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	results, err := doRun(URL, enclave.id, encryptedFunctionData, encryptedInputData, true)
	if err != nil {
		panic(fmt.Sprintf("unable to run function %s", err))
	}

	return results, nil
}

func handleDataNotEncrypted(URL string, enclave *enclave, functionData []byte, inputData []byte) (string, error) {
	encryptedFunction, err := doLocalEncrypt(enclave.attestation, functionData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	encryptedInputData, err := doLocalEncrypt(enclave.attestation, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	return doRun(URL, enclave.id, encryptedFunction, encryptedInputData, false)
}

func doBegin(URL string) (*enclave, error) {
	req, err := http.NewRequest("POST", URL+"/v1/begin", nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed %s", err)
	}

	if res.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("bad status code %d", res.StatusCode)
	}

	resData := BeginResponse{}

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&resData)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response %s", err)
	}

	doc, err := attest.Attest(resData.AttestationDocument)
	if err != nil {
		return nil, fmt.Errorf("attestation failed %s", err)
	}

	return &enclave{id: resData.ID, attestation: *doc}, nil
}

func doRun(URL string, id id.ID, functionData []byte, functionSecret []byte, serverSideEncrypted bool) (string, error) {
	functionDataStr := base64.StdEncoding.EncodeToString(functionData)
	inputDataStr := base64.StdEncoding.EncodeToString(functionSecret)

	runReq := &RunRequest{
		Function: functionDataStr,
		Input:    inputDataStr,
	}

	body, err := json.Marshal(runReq)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/v1/run/%s", URL, id)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status code %d", res.StatusCode)
	}

	resData := &RunResponse{}
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(resData)
	if err != nil {
		return "", err
	}

	return resData.Results, nil
}
