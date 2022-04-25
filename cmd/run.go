package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

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

	if len(args) != 4 {
		panic("expected four args, path to file containing the function, secret for that data, path to file containing input data and secret for that data")
	}

	functionFile := args[0]
	functionSecret := args[1]
	dataFile := args[2]
	dataSecret := args[3]

	functionData, err := ioutil.ReadFile(functionFile)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	inputData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	functionSecretBy, err := base64.StdEncoding.DecodeString(functionSecret)
	if err != nil {
		panic(fmt.Sprintf("unable to decode base64 %s", err))
	}

	inputSecretBy, err := base64.StdEncoding.DecodeString(dataSecret)
	if err != nil {
		panic(fmt.Sprintf("unable to decode base64 %s", err))
	}

	doc, err := doAttest(u)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	functionData = append(functionSecretBy, functionData...)
	encryptedFunctionData, err := doLocalEncrypt(*doc, functionData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	inputData = append(inputSecretBy, inputData...)
	encryptedInputData, err := doLocalEncrypt(*doc, inputData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	results, err := doRun(u, encryptedFunctionData, encryptedInputData)
	if err != nil {
		panic(fmt.Sprintf("unable to run function %s", err))
	}

	fmt.Printf("Successfully ran function. Your results are '%s'\n", results)
}

func doRun(URL string, functionData []byte, functionSecret []byte) (string, error) {
	functionDataStr := base64.StdEncoding.EncodeToString(functionData)
	inputDataStr := base64.StdEncoding.EncodeToString(functionSecret)

	runReq := &RunReq{
		EncryptedFunctionData: functionDataStr,
		EncryptedInputData:    inputDataStr,
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
