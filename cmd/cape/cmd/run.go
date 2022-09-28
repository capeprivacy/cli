package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/sdk"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run {function_id|function_name} [input data]",
	Short: "Run a deployed function with data",
	Long: "Run a deployed function with data, takes function id or function name, path to data, and (optional) checksum.\n" +
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
	runCmd.PersistentFlags().StringP("file", "f", "", "input data file (or '-f -' to accept stdin)")
	runCmd.PersistentFlags().StringP("function-checksum", "", "", "function checksum to attest")
	runCmd.PersistentFlags().StringP("function-hash", "", "", "function hash to attest")
	runCmd.PersistentFlags().StringP("key-policy-hash", "", "", "key policy hash to attest")
	runCmd.PersistentFlags().StringP("key-policy-checksum", "", "", "key policy checksum to attest")
	runCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")

	err := runCmd.PersistentFlags().MarkDeprecated("function-hash", "this flag has been deprecated for renaming, use 'function-checksum' instead")
	if err != nil {
		log.WithError(err).Error("unable to set flag 'function-hash' as deprecated")
	}

	err = runCmd.PersistentFlags().MarkDeprecated("key-policy-hash", "this flag has been deprecated for renaming, use 'key-policy-checksum' instead")
	if err != nil {
		log.WithError(err).Error("unable to set flag 'key-policy-hash' as deprecated")
	}
}

func run(cmd *cobra.Command, args []string) error {
	u := C.EnclaveHost
	insecure := C.Insecure

	if insecure {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if len(args) < 1 {
		return UserError{Msg: "you must pass a function ID or a function name", Err: fmt.Errorf("invalid number of input arguments")}
	}

	if len(args) > 2 {
		return UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")}
	}

	t, err := getAuthToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}

	functionToken, _ := cmd.Flags().GetString("token")
	if functionToken != "" {
		auth.Type = entities.AuthenticationTypeFunctionToken
		auth.Token = functionToken
	}

	function := args[0]
	functionID, err := getFunctionID(function, u)
	if err != nil {
		return UserError{Msg: "invalid input", Err: err}
	}

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return UserError{Msg: "error retrieving file flag", Err: err}
	}

	funcChecksumArg, err := cmd.Flags().GetString("function-checksum")
	if err != nil {
		return UserError{Msg: "error retrieving function-checksum flag", Err: err}
	}

	// Deprecated
	funcHashArg, err := cmd.Flags().GetString("function-hash")
	if err != nil {
		return UserError{Msg: "error retrieving function_hash flag", Err: err}
	}

	var funcChecksum []byte
	if funcChecksumArg != "" {
		funcChecksum, err = hex.DecodeString(funcChecksumArg)
		if err != nil {
			return UserError{Msg: "error reading in checksum", Err: err}
		}
	} else {
		funcChecksum, err = hex.DecodeString(funcHashArg)
		if err != nil {
			return UserError{Msg: "error reading function hash", Err: err}
		}
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	keyChecksumArg, err := cmd.Flags().GetString("key-policy-checksum")
	if err != nil {
		return UserError{Msg: "error retrieving key_checksum flag", Err: err}
	}

	// Deprecated
	keyPolicyHashArg, err := cmd.Flags().GetString("key-policy-hash")
	if err != nil {
		return UserError{Msg: "error retrieving key_policy_hash flag", Err: err}
	}

	var keyChecksum []byte
	if keyChecksumArg != "" {
		keyChecksum, err = hex.DecodeString(keyChecksumArg)
		if err != nil {
			return UserError{Msg: "error reading in key policy checksum", Err: err}
		}
	} else {
		keyChecksum, err = hex.DecodeString(keyPolicyHashArg)
		if err != nil {
			return UserError{Msg: "error reading in key policy checksum", Err: err}
		}
	}

	switch {
	case strings.TrimSpace(file) == "-":
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return UserError{Msg: "unable to read data from stdin", Err: err}
		}
		input = buf.Bytes()
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
		return UserError{Msg: "invalid input", Err: errors.New("please provide input as a string, input file or stdin")}
	}

	results, err := sdk.Run(sdk.RunRequest{
		URL:          u,
		FunctionID:   functionID,
		Data:         input,
		Insecure:     insecure,
		FuncChecksum: funcChecksum,
		KeyChecksum:  keyChecksum,
		PcrSlice:     pcrSlice,
		FunctionAuth: auth,
	})
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	fmt.Println(string(results))
	return nil
}

// TODO: This function is exported for tuner to use. Remove once tuner is using sdk.Run directly
func Run(url string, auth entities.FunctionAuth, functionID string, file string, insecure bool) ([]byte, error) {
	input, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read data file: %w", err)
	}

	// TODO: Tuner may want to verify function checksum later.
	res, err := sdk.Run(sdk.RunRequest{
		URL:          url,
		FunctionID:   functionID,
		Data:         input,
		Insecure:     insecure,
		PcrSlice:     []string{},
		FunctionAuth: auth,
	})
	if err != nil {
		return nil, fmt.Errorf("error processing data: %w", err)
	}

	return res, nil
}

func getFunctionID(function string, URL string) (string, error) {
	functionID := function
	if strings.Contains(function, "/") {
		// It's a function name of format <userName>/<functionName>
		parts := strings.SplitN(function, "/", 2)
		userName, functionName := parts[0], parts[1]

		if userName == "" {
			return "", errors.New("empty username")
		}
		if functionName == "" {
			return "", errors.New("empty function name")
		}

		u, err := url.Parse(URL)
		if err != nil {
			return "", err
		}

		u.Scheme = "https"

		r := sdk.FunctionIDRequest{
			UserName:     userName,
			FunctionName: functionName,
			URL:          u.String(),
		}

		functionID, err := sdk.GetFunctionID(r)
		if err != nil {
			return "", fmt.Errorf("error retrieving function: %w", err)
		}
		return functionID, nil
	}
	// else we assume a functionID was passed
	return functionID, nil
}
