package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/sdk"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt data",
	RunE:  encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().StringP("file", "f", "", "input data file")
}

func encrypt(cmd *cobra.Command, args []string) error {
	input, userError := parseInput(cmd, args)
	if userError != nil {
		return userError
	}

	keyReq, err := GetKeyRequest()
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

// TODO: Run could use this function.
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
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return nil, &UserError{Msg: "unable to read data from stdin", Err: err}
		}
		input = buf.Bytes()
	}

	return input, nil
}
