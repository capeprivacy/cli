package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/sdk"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt (<input data> | -f <input file>)",
	Short: "Encrypt local data",
	Long: `Cape Encrypt

Encrypt local data for use with cape functions.

Retrieves a user-specific public key and encrypts local data so that it may be
safely shared and used as input to cape functions. Results are output to stdout
so you can easily pipe them elsewhere.

By default, cape encrypt will use your public key to encrypt data.
You can specify another user with --username.
`,
	Example: `  cape encrypt "foo"                       Encrypt a string
  echo '1234' | cape encrypt               Encrypt input data read from stdin
  cape encrypt -f example.txt              Encrypt data read from a file named "example.txt"
  cape encrypt hello --username capedocs   Encrypt using capedocs publickey`,
	RunE: encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().StringP("file", "f", "", "input data file (or '-f -' to accept stdin)")
	encryptCmd.PersistentFlags().String("username", "", "username of the key owner")
}

func encrypt(cmd *cobra.Command, args []string) error {
	username, err := cmd.Flags().GetString("username")
	if err != nil {
		return err
	}

	if username == "" {
		t, err := getTokenResponse()
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("couldn't get username from ~/.config/cape/auth id token, are you logged in? (run `cape login`)")
		}

		j, err := jwt.ParseInsecure([]byte(t.IDToken))
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("couldn't get username from ~/.config/cape/auth id token, are you logged in? (run `cape login`)")
		}

		n, ok := j.Get("nickname")
		if !ok {
			cmd.SilenceUsage = true
			return fmt.Errorf("couldn't get username from the `id_token` in ~/.config/cape/auth, are you logged in? (run `cape login`)")
		}

		username = n.(string)
	}

	input, userError := parseInput(cmd, args)
	if err != nil {
		return userError
	}

	// at this point the command was used properly
	cmd.SilenceUsage = true
	secret, err := capeEncrypt(string(input), username)
	if err != nil {
		return err
	}

	if _, err := cmd.OutOrStdout().Write([]byte(secret + "\n")); err != nil {
		return err
	}

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

var capeEncrypt = sdk.Encrypt
