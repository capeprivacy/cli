package cmd

import (
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
