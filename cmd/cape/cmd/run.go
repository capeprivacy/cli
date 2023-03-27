package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/capeprivacy/attest/attest"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/sdk"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run { <function_id> | <user_name>/<function_name> } [input data]",
	Short: "Run a deployed function with data",
	Long: `Run a deployed function with data.

Results are output to stdout so you can easily pipe them elsewhere.`,
	Example: `
	# Run a function named 'echo' created by user 'capedocs'
	$ cape run capedocs/echo 'Hello World'

	# Run a function with input data provided on stdin
	$ echo '1234' | cape run capedocs/echo -f -

	# Filter a function's output through sed
	$ cape run capedocs/echo 'Hello World' | sed 's/Hello/Hola/'

	# Run while verifying PCRs
	# PCRs can be retrieved with: 'cape get-pcrs'
	# PCRs are specified through a string array of the form: [<PCR_number>:<PCR_value>], example below
	$ cape run capedocs/echo 5 --pcr=0:placeholderPCR0,8:placeholderPCR8
`,
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

	runCmd.PersistentFlags().StringP("token", "t", "", "authorization token to use")
	runCmd.PersistentFlags().StringP("file", "f", "", "input data file (or '-f -' to accept stdin)")
	runCmd.PersistentFlags().StringP("function-checksum", "", "", "function checksum to attest")
	runCmd.PersistentFlags().StringP("key-policy-checksum", "", "", "key policy checksum to attest")
	runCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
}

func run(cmd *cobra.Command, args []string) error {
	u := C.EnclaveHost
	insecure := C.Insecure
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	formatter, ok := runFormatters[output]
	if !ok {
		return fmt.Errorf("unknown output option: %s", output)
	}

	if len(args) < 1 {
		return UserError{Msg: "you must pass a function ID or a function name", Err: fmt.Errorf("invalid number of input arguments")}
	}

	if len(args) > 2 {
		return UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")}
	}

	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken}
	token, _ := cmd.Flags().GetString("token")
	if token != "" {
		auth.Token = token
	} else {
		token, err := getAuthToken()
		if err != nil {
			return err
		}
		auth.Token = token
	}

	functionID := args[0]
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return UserError{Msg: "error retrieving file flag", Err: err}
	}

	funcChecksumArg, err := cmd.Flags().GetString("function-checksum")
	if err != nil {
		return UserError{Msg: "error retrieving function-checksum flag", Err: err}
	}

	var funcChecksum []byte
	if funcChecksumArg != "" {
		funcChecksum, err = hex.DecodeString(funcChecksumArg)
		if err != nil {
			return UserError{Msg: "error reading in checksum", Err: err}
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

	var keyChecksum []byte
	if keyChecksumArg != "" {
		keyChecksum, err = hex.DecodeString(keyChecksumArg)
		if err != nil {
			return UserError{Msg: "error reading in key policy checksum", Err: err}
		}
	}

	input, err := getInput(cmd, args, file)
	if err != nil {
		return err
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
		return fmt.Errorf("run request failed: %w", err)
	}

	return formatter(*results)
}

func isValidFunctionID(functionID string) bool {
	// an alphanumeric string of length 22 is considered a syntactically correct functionID
	return regexp.MustCompile(`^[a-zA-Z0-9]{22}$`).MatchString(functionID)
}

func splitFunctionName(function string) (string, string, error) {
	userName, functionName, found := strings.Cut(function, "/")

	if !found {
		return "", "", errors.New("no '/' in function name")
	}

	if userName == "" {
		return "", functionName, errors.New("empty username")
	}

	if functionName == "" {
		return userName, "", errors.New("empty function name")
	}
	return userName, functionName, nil
}

func getInput(cmd *cobra.Command, args []string, file string) ([]byte, error) {
	switch {
	case strings.TrimSpace(file) == "-":
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return nil, UserError{Msg: "unable to read data from stdin", Err: err}
		}
		return buf.Bytes(), nil
	case file != "":
		// input file was provided
		input, err := os.ReadFile(file)
		if err != nil {
			return nil, UserError{Msg: "unable to read data file", Err: err}
		}
		return input, nil
	case len(args) == 2:
		// read input from  command line string
		return []byte(args[1]), nil
	default:
		return nil, UserError{Msg: "invalid input", Err: errors.New("please provide input as a string, input file or stdin")}
	}
}

var runFormatters = map[string]func(result cli.RunResult) error{
	"plain": runPlain,
	"json":  runJSON,
}

func runPlain(result cli.RunResult) error {
	fmt.Println(string(result.Message))
	return nil
}

func runJSON(result cli.RunResult) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		Output            string                 `json:"output"`
		Checksums         cli.Checksums          `json:"checksums"`
		SignedResults     []byte                 `json:"signed_results"`
		AttestationDoc    *attest.AttestationDoc `json:"attestation_doc"`
		RawAttestationDoc []byte                 `json:"raw_attestation_doc"`
	}{
		Output:            string(result.Message),
		Checksums:         result.Checksums,
		SignedResults:     result.SignedResults,
		AttestationDoc:    result.DecodedAttestationDocument,
		RawAttestationDoc: result.RawAttestationDocument,
	})
}
