package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
)

// runCmd represents the request command
var runCmd = &cobra.Command{
	Use:   "run function_id [input data]",
	Short: "run a deployed function with data",
	Long: "Run a deployed function with data, takes function id and path to data.\n" +
		"Run will also read input data from stdin, example: \"echo '1234' | cape run id\".\n" +
		"Results are output to stdout so you can easily pipe them elsewhere.",
	RunE: run,
}

type RunRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce     string `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type RunResponse struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

type AttestationResponse struct {
	AttestationDoc string `json:"attestation_doc"`
}

type Message struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

type ErrorRunResponse struct {
	Message string `json:"message"`
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.PersistentFlags().StringP("token", "t", "", "token to use")
	runCmd.PersistentFlags().StringP("file", "f", "", "input data file")
}

func run(cmd *cobra.Command, args []string) error {
	u := C.Hostname
	insecure := C.Insecure

	if len(args) < 1 {
		return fmt.Errorf("you must pass a function ID")
	}

	functionID := args[0]

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return fmt.Errorf("error retrieving file flag")
	}

	switch {
	case file != "":
		// input file was provided
		input, err = ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("unable to read data file: %w", err)
		}
	case len(args) == 2:
		// read input from  command line string
		input = []byte(args[1])
	default:
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return fmt.Errorf("unable to read data from stdin: %w", err)
		}
		input = buf.Bytes()
	}

	results, err := doRun(u, functionID, input, insecure)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	log.Infof("Success! Results from your function:\n")
	fmt.Println(string(results))
	return nil
}

// this function is exported for tuner to use
func Run(url string, functionID string, file string, insecure bool) error {
	input, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("unable to read data file: %w", err)
	}

	_, err = doRun(url, functionID, input, insecure)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	return nil
}

func doRun(url string, functionID string, data []byte, insecure bool) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/v1/run/%s", url, functionID)

	c, res, err := websocketDial(endpoint, insecure)
	if err != nil {
		log.Error("error dialing websocket", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if res != nil {
			var e ErrorMsg
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				return nil, err
			}
			res.Body.Close()
			return nil, fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
		}
		return nil, err
	}
	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, err
	}

	token, err := getAuthToken()
	if err != nil {
		return nil, err
	}

	req := RunRequest{Nonce: nonce, AuthToken: token}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = c.WriteJSON(req)
	if err != nil {
		return nil, errors.Wrap(err, "error writing run request")
	}

	log.Debug("* Waiting for attestation document...")

	var msg Message
	err = c.ReadJSON(&msg)
	if err != nil {
		log.Println("error reading attestation doc")
		return nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return nil, err
	}

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, err := attest.Attest(msg.Message, rootCert)
	if err != nil {
		log.Println("error attesting")
		return nil, err
	}

	encryptedData, err := crypto.LocalEncrypt(*doc, data)
	if err != nil {
		log.Println("error encrypting")
		return nil, err
	}

	log.Debug("\n> Sending Encrypted Inputs")
	err = writeData(c, encryptedData)
	if err != nil {
		return nil, err
	}

	log.Debug("* Waiting for function results...")

	resData := &RunResponse{}
	err = c.ReadJSON(&resData)
	if err != nil {
		return nil, err
	}
	log.Debugf("< Received Function Results.")

	return resData.Message, nil
}

func writeData(conn *websocket.Conn, data []byte) error {
	w, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = w.Write(data)
	if err != nil {
		return err
	}

	return nil
}
