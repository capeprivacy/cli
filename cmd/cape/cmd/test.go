package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/capetest"
	czip "github.com/capeprivacy/cli/zip"
)

var testCmd = &cobra.Command{
	Use:   "test directory [input]",
	Short: "Test your function with Cape",
	Long: "Test your function with Cape\n" +
		"Test will also read input data from stdin, example: \"echo '1234' | cape test dir\".\n" +
		"Results are output to stdout so you can easily pipe them elsewhere",
	RunE: Test,
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.PersistentFlags().StringP("file", "f", "", "input data file")
}

func Test(cmd *cobra.Command, args []string) error {
	presets, err := getPresetArgs()
	if err != nil {
		return fmt.Errorf("error reading presets file: %w", err)
	}

	u, err := cmd.Flags().GetString("url")
	if err != nil {
		if presets.Url != "" {
			u = presets.Url
		} else {
			return fmt.Errorf("flag not found: %w", err)
		}
	}

	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		if presets.Insecure {
			insecure = presets.Insecure
		} else {
			return fmt.Errorf("flag not found: %w", err)
		}
	}

	if len(args) < 1 || len(args) > 2 {
		if err := cmd.Usage(); err != nil {
			return err
		}

		return nil
	}

	fnZip, err := czip.Create(args[0])
	if err != nil {
		return err
	}

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

	token, err := authToken()
	if err != nil {
		return err
	}

	res, err := test(capetest.TestRequest{Function: fnZip, Input: input, AuthToken: token}, u+"/v1/test", insecure)
	if err != nil {
		return err
	}

	if _, err := cmd.OutOrStdout().Write(res.Message); err != nil {
		return err
	}

	return nil
}

var authToken = getAuthToken
var test = capetest.CapeTest
