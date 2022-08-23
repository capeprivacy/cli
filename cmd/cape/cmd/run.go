package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/capeprivacy/cli/entities"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/sdk"
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

	t, err := getAuthToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}
	if functionToken != "" {
		auth.Type = entities.AuthenticationTypeFunctionToken
		auth.Token = functionToken
	}

	results, err := sdk.Run(sdk.RunRequest{
		URL:           u,
		FunctionID:    functionID,
		Data:          input,
		Insecure:      insecure,
		FuncHash:      funcHash,
		KeyPolicyHash: keyPolicyHash,
		PcrSlice:      pcrSlice,
		FunctionAuth:  auth,
	})
	if err != nil {
		return fmt.Errorf("error processing data: %w", err)
	}

	fmt.Println(string(results))
	return nil
}

// This function is exported for tuner to use.
func Run(url string, auth entities.FunctionAuth, functionID string, file string, insecure bool) ([]byte, error) {
	input, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read data file: %w", err)
	}

	// TODO: Tuner may want to verify function hash later.
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
