package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/capetest"
	czip "github.com/capeprivacy/cli/zip"
)

var testCmd = &cobra.Command{
	Use:   "test directory [input]",
	Short: "Test your function with Cape",
	Long: "Test your function with Cape\n" +
		"Test will also read input data from stdin, example: \"echo '1234' | cape test dir\".\n" +
		"Results are output to stdout so you can easily pipe them elsewhere",
	RunE: func(cmd *cobra.Command, args []string) error {
		// check values
		err := Test(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.PersistentFlags().StringP("file", "f", "", "input data file")
}

func Test(cmd *cobra.Command, args []string) error {
	// Set test to be in verbose mode by default.
	log.SetLevel(log.DebugLevel)
	u := C.EnclaveHost
	insecure := C.Insecure

	if len(args) < 1 || len(args) > 2 {
		return UserError{err: fmt.Errorf("invalid number of input arguments")}
	}

	fnZip, err := czip.Create(args[0])
	if err != nil {
		return UserError{err: err}
	}

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return UserError{err: fmt.Errorf("error retrieving file flag")}
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{err: fmt.Errorf("error retrieving pcr flags %s", err)}
	}

	switch {
	case file != "":
		// input file was provided
		input, err = ioutil.ReadFile(file)
		if err != nil {
			return UserError{err: fmt.Errorf("unable to read data file: %w", err)}
		}
	case len(args) == 2:
		// read input from  command line string
		input = []byte(args[1])
	default:
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return UserError{err: fmt.Errorf("unable to read data from stdin: %w", err)}
		}
		input = buf.Bytes()
	}

	token, err := authToken()
	if err != nil {
		return UserError{err: err}
	}

	res, err := test(capetest.TestRequest{Function: fnZip, Input: input, AuthToken: token}, u+"/v1/test", insecure, pcrSlice)
	if err != nil {
		return err
	}

	if _, err := cmd.OutOrStdout().Write(res.Message); err != nil {
		return err
	}

	log.Info()
	return nil
}

var authToken = getAuthToken
var test = capetest.CapeTest
