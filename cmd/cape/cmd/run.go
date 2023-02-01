package cmd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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

	if len(args) < 1 {
		return UserError{Msg: "you must pass a function ID or a function name", Err: fmt.Errorf("invalid number of input arguments")}
	}

	if len(args) > 2 {
		return UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")}
	}

	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken}
	token, _ := cmd.Flags().GetString("token")
	if token != "" {
		issuer, err := getTokenIssuer(token)
		if err != nil {
			return err
		}
		// if its a passed token not issued by us assume its a function token
		if issuer != "cape-privacy" {
			auth.Type = entities.AuthenticationTypeFunctionToken
		}
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

	fmt.Println(string(results))
	return nil
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

func getTokenIssuer(token string) (string, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithVerify(false))
	if err != nil {
		return "", err
	}

	return parsed.Issuer(), nil
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
