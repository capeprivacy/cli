package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/capeprivacy/cli/entities"

	"github.com/capeprivacy/cli/sdk"
)

const (
	deleteHelp = `Delete a deployed function, takes function id.

Usage:
  cape delete function_id [flags]

Flags:
  -h, --help   help for delete

Global Flags:
  -c, --config string   config file (default "$HOME/.config/cape/presets.json")
  -u, --url string      cape cloud URL (default "wss://enclave.capeprivacy.com")
  -v, --verbose         verbose output
`

	deleteUsage = `Usage:
  cape delete function_id [flags]

Flags:
  -h, --help   help for delete

Global Flags:
  -c, --config string   config file (default "$HOME/.config/cape/presets.json")
  -u, --url string      cape cloud URL (default "wss://enclave.capeprivacy.com")
  -v, --verbose         verbose output

`
)

func TestDeleteoArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"delete"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stdout.String(), deleteUsage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestDeleteTooManyArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"delete", "one", "extra"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stdout.String(), deleteUsage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestDeleteBadFunction(t *testing.T) {
	cmd, _, stderr := getCmd()
	cmd.SetArgs([]string{"delete", "invalid"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), "Error: delete failed: server response code 404\n"; got != want {
		t.Errorf("didn't get expected stderr, got %s, wanted %s", got, want)
	}
}

func TestDeleteServerError(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"delete", "foo"})

	errMsg := "Error: delete failed: server response code"
	test = func(testReq sdk.TestRequest, endpoint string) (*entities.RunResults, error) {
		return nil, errors.New(errMsg)
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), errMsg; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), ""; got != want {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestDeleteHelp(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"delete", "-h"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), deleteHelp; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected output, got %s, wanted %s", got, want)
	}
}
