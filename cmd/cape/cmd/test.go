package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/url"

	"github.com/capeprivacy/cli/capetest"
	czip "github.com/capeprivacy/cli/zip"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test directory [input]",
	Short: "Test your function with Cape",
	Long: "Test your function with Cape\n" +
		"Test will also read input data from stdin, example: \"echo '1234' | cape run id\".\n" +
		"Results are output to stdout so you can easily pipe them elsewhere",
	RunE: Test,
}

func init() {
	rootCmd.AddCommand(testCmd)
}

func wsURL(origURL string) string {
	u, _ := url.Parse(origURL)
	u.Scheme = "ws"

	return u.String()
}

func Test(cmd *cobra.Command, args []string) error {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		return fmt.Errorf("flag not found: %w", err)
	}

	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("flag not found: %w", err)
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

	stdin := cmd.InOrStdin()
	if err != nil {
		return err
	}

	var input []byte
	if len(args) == 2 {
		input = []byte(args[1])
	} else {
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, stdin); err != nil {
			return err
		}
		input = buf.Bytes()
	}

	res, err := test(capetest.TestRequest{Function: fnZip, Input: input}, wsURL(u), insecure)
	if err != nil {
		return err
	}

	if _, err := cmd.OutOrStdout().Write(res.Message); err != nil {
		return err
	}

	return nil
}

var test = capetest.CapeTest
