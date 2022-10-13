package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/sdk"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt (<input data> | -f <input file>)",
	Short: "Encrypt local data",
	Long: `Encrypt local data for use with cape functions.

Retrieves a user-specific public key and encrypts local data so that it may be
safely shared and used as input to cape functions. Results are output to stdout
so you can easily pipe them elsewhere.
`,
	Example: `
	# Encrypt a string
	cape encrypt "foo"
	
	# Encrypt input data read from stdin
	echo '1234' | cape encrypt
	
	# Encrypt data read from a file named "example.txt"
	cape encrypt -f example.txt
`,
	RunE: encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().StringP("file", "f", "", "input data file (or '-f -' to accept stdin)")
	encryptCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against, used while getting key for the first time")
}

func encrypt(cmd *cobra.Command, args []string) error {
	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	input, userError := parseInput(cmd, args)
	if userError != nil {
		return userError
	}

	keyReq, err := GetKeyRequest(pcrSlice)
	if err != nil {
		return err
	}

	result, err := sdk.Encrypt(keyReq, input)
	if err != nil {
		return err
	}

	fmt.Println(result)

	return nil
}

func parseInput(cmd *cobra.Command, args []string) ([]byte, *UserError) {
	if len(args) > 1 {
		return nil, &UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")}
	}

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return nil, &UserError{Msg: "error retrieving file flag", Err: err}
	}

	switch {
	case strings.TrimSpace(file) == "-":
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return nil, &UserError{Msg: "unable to read data from stdin", Err: err}
		}
		input = buf.Bytes()
	case file != "":
		// input file was provided
		input, err = os.ReadFile(file)
		if err != nil {
			return nil, &UserError{Msg: "unable to read data file", Err: err}
		}
	case len(args) == 1:
		// read input from  command line string
		input = []byte(args[0])
	default:
		return nil, &UserError{Msg: "invalid input", Err: errors.New("please provide input as a string, input file or stdin")}
	}

	return input, nil
}
