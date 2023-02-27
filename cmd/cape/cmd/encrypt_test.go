package cmd

import (
	"errors"
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

func TestEncryptEmpty(t *testing.T) {
	capeEncrypt = func(message, username string, options ...sdk.Option) (string, error) {
		return "cape:secret", nil
	}

	cmd, _, _ := getCmd()
	cmd.SetArgs([]string{"encrypt", "", "--username", "bendecoste"})
	wantErr := UserError{Msg: "unable to encrypt", Err: errors.New("input is empty")}
	if err := cmd.Execute(); err.Error() != wantErr.Error() {
		t.Fatalf("expected error: %s", wantErr.Error())
	}
}
