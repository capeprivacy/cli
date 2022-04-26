package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/capeprivacy/cli/attest"
	"github.com/spf13/cobra"
)

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

	doc, err := doAttest(u)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	encryptedData := EncryptedData{}
	err = json.Unmarshal(functionData, &encryptedData)
	if err == nil {
		results, err := handleDataEncrypted(u, *doc, functionData, inputData)
		if err != nil {
			panic(fmt.Sprintf("unable to handle encrypted data %s", err))
		}

		fmt.Printf("Successfully ran function. Your results are '%s'\n", results)
		return
	}

	results, err := handleDataNotEncrypted(u, *doc, functionData, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to handle not already encrypted data %s", err))
	}

	fmt.Printf("Successfully ran function. Your results are '%s'\n", results)
}

func handleDataEncrypted(URL string, doc attest.AttestationDoc, functionData []byte, inputData []byte) (string, error) {
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
	encryptedFunctionData, err := doLocalEncrypt(doc, functionData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	inputData = append(encryptedInput.Secret, encryptedInput.Data...)
	encryptedInputData, err := doLocalEncrypt(doc, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	results, err := doRun(URL, encryptedFunctionData, encryptedInputData, true)
	if err != nil {
		panic(fmt.Sprintf("unable to run function %s", err))
	}

	return results, nil
}

func handleDataNotEncrypted(URL string, doc attest.AttestationDoc, functionData []byte, inputData []byte) (string, error) {
	encryptedFunction, err := doLocalEncrypt(doc, functionData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	encryptedInputData, err := doLocalEncrypt(doc, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	return doRun(URL, encryptedFunction, encryptedInputData, false)
}

func doRun(URL string, functionData []byte, functionSecret []byte, serverSideEncrypted bool) (string, error) {
	functionDataStr := base64.StdEncoding.EncodeToString(functionData)
	inputDataStr := base64.StdEncoding.EncodeToString(functionSecret)

	runReq := &RunReq{
		EncryptedFunctionData: functionDataStr,
		EncryptedInputData:    inputDataStr,
		serverSideEncrypted:   serverSideEncrypted,
	}

	body, err := json.Marshal(runReq)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", URL+"/v1/run", bytes.NewBuffer(body))
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

	resData := &RunRes{}
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(resData)
	if err != nil {
		return "", err
	}

	return resData.Results, nil
}
