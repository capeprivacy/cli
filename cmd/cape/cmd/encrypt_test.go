package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/capeprivacy/cli/sdk"
)

func TestEncrypt(t *testing.T) {
	capeEncrypt = func(message, username string, options ...sdk.Option) (string, error) {
		return "cape:secret", nil
	}

	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"encrypt", "hello", "--username", "bendecoste"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), "cape:secret\n"; got != want {
		t.Fatalf("didn't get expected output, got %s, wanted %s", got, want)
	}
}

func TestEncryptBadInput(t *testing.T) {
	for _, tt := range []struct {
		name      string
		args      []string
		wantError error
	}{
		{
			name:      "empty input",
			args:      []string{"encrypt", "", "--username", "bendecoste"},
			wantError: UserError{Msg: "unable to encrypt", Err: errors.New("input is empty")},
		},
		{
			name:      "too many inputs",
			args:      []string{"encrypt", "", "", "--username", "bendecoste"},
			wantError: UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			capeEncrypt = func(message, username string, options ...sdk.Option) (string, error) {
				return "cape:secret", nil
			}
			cmd, _, _ := getCmd()
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err.Error() != tt.wantError.Error() {
				t.Fatalf("expected error: %s, got: %s", tt.wantError.Error(), err.Error())
			}
		})
	}
}
