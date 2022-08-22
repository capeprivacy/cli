package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/protocol"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run function_id [input data]",
	Short: "Run a deployed function with data",
	Long: "Run a deployed function with data, takes function id, path to data, and (optional) function hash.\n" +
		"Run will also read input data from stdin, example: \"echo '1234' | cape run id\".\n" +
		"Results are output to stdout so you can easily pipe them elsewhere.",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := run(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
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

	runCmd.PersistentFlags().StringP("token", "t", "", "function token to use")
	runCmd.PersistentFlags().StringP("file", "f", "", "input data file")
	runCmd.PersistentFlags().StringP("function-hash", "", "", "function hash to attest")
	runCmd.PersistentFlags().StringP("key-policy-hash", "", "", "key policy hash to attest")
	runCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
}

func run(cmd *cobra.Command, args []string) error {
	u := C.EnclaveHost
	insecure := C.Insecure

	if len(args) < 1 {
		return UserError{Msg: "you must pass a function ID", Err: fmt.Errorf("invalid number of input arguments")}
	}

	if len(args) > 2 {
		return UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")}
	}

	functionID := args[0]

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return UserError{Msg: "error retrieving file flag", Err: err}
	}

	funcHashArg, err := cmd.Flags().GetString("function-hash")
	if err != nil {
		return UserError{Msg: "error retrieving function_hash flag", Err: err}
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	funcHash, err := hex.DecodeString(funcHashArg)
	if err != nil {
		return UserError{Msg: "error reading function hash", Err: err}
	}

	keyPolicyHashArg, err := cmd.Flags().GetString("key-policy-hash")
	if err != nil {
		return UserError{Msg: "error retrieving key_policy_hash flag", Err: err}
	}

	keyPolicyHash, err := hex.DecodeString(keyPolicyHashArg)
	if err != nil {
		return UserError{Msg: "error reading key policy hash", Err: err}
	}

	functionToken, _ := cmd.Flags().GetString("token")

	switch {
	case file != "":
		// input file was provided
		input, err = os.ReadFile(file)
		if err != nil {
			return UserError{Msg: "unable to read data file", Err: err}
		}
	case len(args) == 2:
		// read input from  command line string
		input = []byte(args[1])

	default:
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return UserError{Msg: "unable to read data from stdin", Err: err}
		}
		input = buf.Bytes()
	}

	authType := entities.AuthenticationTypeAuth0
	if functionToken != "" {
		authType = entities.AuthenticationTypeFunctionToken
	}

	a := entities.FunctionAuth{
		Token: functionToken,
		Type:  authType,
	}
	results, err := doRun(u, functionID, input, insecure, funcHash, a, keyPolicyHash, pcrSlice)
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	fmt.Println(string(results))
	return nil
}

// This function is exported for tuner to use.
func Run(url string, token string, functionID string, file string, insecure bool) ([]byte, error) {
	input, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read data file: %w", err)
	}

	a := entities.FunctionAuth{
		Token: token,
		Type:  entities.AuthenticationTypeAuth0,
	}

	// TODO: Tuner may want to verify function hash later.
	res, err := doRun(url, functionID, input, insecure, nil, a, nil, []string{})
	if err != nil {
		return nil, fmt.Errorf("error processing data: %w", err)
	}

	return res, nil
}

func doRun(url string, functionID string, data []byte, insecure bool, funcHash []byte, auth entities.FunctionAuth, keyPolicyHash []byte, pcrSlice []string) ([]byte, error) { //nolint:gocognit
	endpoint := fmt.Sprintf("%s/v1/run/%s", url, functionID)

	c, res, err := websocketDial(endpoint, insecure, string(auth.Type), auth.Token)
	if err != nil {
		log.Error("error dialing websocket: ", err)
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
	defer c.Close()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return nil, err
	}

	p := protocol.Protocol{Websocket: c}

	req := entities.StartRequest{Nonce: []byte(nonce), AuthToken: auth.Token}
	log.Debug("\n> Sending Nonce and Auth Token")
	err = p.WriteStart(req)
	if err != nil {
		return nil, errors.Wrap(err, "error writing run request")
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
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
	doc, userData, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Println("error attesting")
		return nil, err
	}

	if userData.FuncHash == nil && len(funcHash) > 0 {
		return nil, fmt.Errorf("did not receive function hash from enclave")
	}

	// If function hash as an optional parameter has not been specified by the user, then we don't check the value.
	if len(funcHash) > 0 && !reflect.DeepEqual(funcHash, userData.FuncHash) {
		return nil, fmt.Errorf("returned function hash did not match provided, got: %x, want %x", userData.FuncHash, funcHash)
	}

	if userData.KeyPolicyHash == nil && len(keyPolicyHash) > 0 {
		return nil, fmt.Errorf("did not receive key policy hash from enclave")
	}

	if len(keyPolicyHash) > 0 && !reflect.DeepEqual(keyPolicyHash, userData.KeyPolicyHash) {
		return nil, fmt.Errorf("returned key policy hash did not match provided, got: %x, want %x", userData.KeyPolicyHash, keyPolicyHash)
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

	resData, err := p.ReadRunResults()
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
