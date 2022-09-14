package cmd

import (
	"errors"
	"strings"
	"testing"
)

const (
	listHelp = `List all deployed functions for your user.`

	listUsage = `Usage:
  cape list [flags]`
)

func TestlistArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"list"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stdout.String(), deleteUsage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestListTooManyArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"list", "extra"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stdout.String(), listUsage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestListServerError(t *testing.T) {
	cmd, _, stderr := getCmd()
	cmd.SetArgs([]string{"list"})

	errMsg := "Error: error calling list endpoint: list failed"
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		authToken = getAuthToken
	}()

	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), errMsg; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}
}

func TestListHelp(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"list", "-h"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), listHelp; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected output, got %s, wanted %s", got, want)
	}
}
