package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/go-kit/id"
	"github.com/spf13/cobra"
)

type StartRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce string `json:"nonce"`
}

type StartResponse struct {
	ID                  id.ID     `json:"id"`
	AttestationDocument string    `json:"attestation_document"`
	CreatedAt           time.Time `json:"created_at"`
}

type TestRequest struct {
	Function string `json:"function"`
	Input    string `json:"input"`

	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce string `json:"nonce"`
}

type Outputs struct {
	Data       string `json:"data"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitStatus string `json:"exit_status"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type enclave struct {
	id          id.ID
	attestation attest.AttestationDoc
}

// testCmd represents the request command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "test with function and data",
	Long:  "test with function and data, takes path to function and path to data",
	Run:   test,
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.PersistentFlags().StringP("token", "t", "", "token to use")
}

func test(cmd *cobra.Command, args []string) {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Errorf("flag not found: %s", err)
		return
	}

	if len(args) != 2 {
		log.Error("Error, invalid arguments")
		_ = cmd.Help()
		return
	}

	functionFile := args[0]
	dataFile := args[1]

	functionData, err := ioutil.ReadFile(functionFile)
	if err != nil {
		log.Errorf("unable to read function file: %s", err)
		return
	}

	inputData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		log.Errorf("unable to read data file: %s", err)
		return
	}

	enclave, err := doStart(u)
	if err != nil {
		log.Errorf("unable to start enclave: %s", err)
		return
	}

	results, err := handleData(u, enclave, functionData, inputData)
	if err != nil {
		log.Errorf("unable to run test %s", err)
		return
	}

	fmt.Printf("Successfully ran function. Your results are: %+v \n", results)
}

func handleData(url string, enclave *enclave, functionData []byte, inputData []byte) (*Outputs, error) {
	encryptedFunction, err := crypto.LocalEncrypt(enclave.attestation, functionData)
	if err != nil {
		log.Errorf("unable to encrypt data %s", err)
	}

	encryptedInputData, err := crypto.LocalEncrypt(enclave.attestation, inputData)
	if err != nil {
		log.Errorf("unable to encrypt data %s", err)
	}

	return doTest(url, enclave.id, encryptedFunction, encryptedInputData)
}

func doStart(url string) (*enclave, error) {
	reqData := StartRequest{
		Nonce: getNonce(),
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url+"/v1/start", bytes.NewBuffer(body))
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

	resData := StartResponse{}

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

func doTest(url string, id id.ID, encryptedFunction []byte, encryptedData []byte) (*Outputs, error) {
	functionDataStr := base64.StdEncoding.EncodeToString(encryptedFunction)
	inputDataStr := base64.StdEncoding.EncodeToString(encryptedData)

	runReq := &TestRequest{
		Function: functionDataStr,
		Input:    inputDataStr,
		Nonce:    getNonce(),
	}

	body, err := json.Marshal(runReq)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/v1/test/%s", url, id)
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

func getNonce() string {
	buf := make([]byte, 16)

	if _, err := rand.Reader.Read(buf); err != nil {
		log.WithError(err).Error("failed to get nonce")
	}

	return base64.StdEncoding.EncodeToString(buf)
}
