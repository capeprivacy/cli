package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
)

// runCmd represents the request command
var runCmd = &cobra.Command{
	Use:   "run [function id] [input data]",
	Short: "run a deployed function with data",
	Long:  "run a deployed function with data, takes function id and path to data",
	RunE:  run,
}

type RunRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce string `json:"nonce"`
}

type RunResponse struct {
	Data []byte `json:"data"`
}

type AttestationResponse struct {
	AttestationDoc string `json:"attestation_doc"`
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

	return Run(u, dataFile, functionID)
}

func Run(u string, dataFile string, functionID string) error {
	inputData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		return fmt.Errorf("unable to read data file: %w", err)
	}

	results, err := doRun(u, functionID, inputData)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Success! Results from your function")
	fmt.Println(string(results))
	return nil
}

func doRun(url string, functionID string, data []byte) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/v1/run/%s", url, functionID)

	c, res, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		log.Println("error dialing websocket", res)
		return nil, err
	}

	req := RunRequest{Nonce: getNonce()}
	err = c.WriteJSON(req)
	if err != nil {
		log.Println("error writing deploy request")
		return nil, err
	}

	_, docB64, err := c.ReadMessage()
	if err != nil {
		log.Println("error reading attestation doc")
		return nil, err
	}

	doc, err := attest.Attest(docB64)
	if err != nil {
		log.Println("error attesting")
		return nil, err
	}

	encryptedData, err := crypto.LocalEncrypt(*doc, data)
	if err != nil {
		log.Println("error encrypting")
		return nil, err
	}

	webWriter, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return nil, err
	}

	_, err = webWriter.Write(encryptedData)
	if err != nil {
		return nil, err
	}

	webWriter.Close()

	resData := &RunResponse{}
	err = c.ReadJSON(&resData)
	if err != nil {
		log.Fatal(err)
	}

	return resData.Data, nil
}
