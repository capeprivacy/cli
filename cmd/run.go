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
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
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

	results, err := handleData(u, enclave, functionData, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to handle not already encrypted data %s", err))
	}

	fmt.Printf("Successfully ran function. Your results are '%s'\n", results)
}

func handleData(URL string, enclave *enclave, functionData []byte, inputData []byte) (string, error) {
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

func doLocalEncrypt(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) {
	buf := bytes.NewBuffer(doc.PublicKey)
	reader := keyset.NewBinaryReader(buf)
	khPub, err := keyset.ReadWithNoSecrets(reader)
	if err != nil {
		return nil, fmt.Errorf("read pubic key %s", err)
	}

	encrypt, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypt.Encrypt(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	return ciphertext, nil
}
