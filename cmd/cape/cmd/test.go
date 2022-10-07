package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/sdk"
	czip "github.com/capeprivacy/cli/zip"
)

var testCmd = &cobra.Command{
	Use:   "test <directory> [input]",
	Short: "Test your function with Cape",
	Long: `Test your function with Cape

Results are output to stdout so you can easily pipe them elsewhere`,
	Example: `
	# Test code in a dir named "func/" with "1234" as input
	$ echo '1234' | cape test func/ -f -

	# Test code in "func/" and filter output through jq
	$ echo '1234' | cape test func/ -f - | jq .
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := Test(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.PersistentFlags().StringP("file", "f", "", "input data file (or '-f -' to accept stdin)")
	testCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
}

func Test(cmd *cobra.Command, args []string) error {
	// Set test to be in verbose mode by default.
	log.SetLevel(log.DebugLevel)
	u := C.EnclaveHost
	insecure := C.Insecure

	if len(args) < 1 || len(args) > 2 {
		return UserError{Msg: "you must provide input data", Err: fmt.Errorf("invalid number of input arguments")}
	}

	fnZip, err := czip.Create(args[0])
	if err != nil {
		return UserError{Msg: "unable to zip specified directory", Err: err}
	}

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return UserError{Msg: "you must specify a file correctly", Err: err}
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
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

	token, err := authToken()
	if err != nil {
		return err
	}

	res, err := test(sdk.TestRequest{Function: fnZip, Input: input, AuthToken: token, Insecure: insecure}, u+"/v1/test", pcrSlice)
	if err != nil {
		return err
	}

	if _, err := cmd.OutOrStdout().Write(res.Message); err != nil {
		return err
	}

	return nil
}

var authToken = getAuthToken
var test = sdk.Test
