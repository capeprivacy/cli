package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToken(t *testing.T) {
	cmd, _, _ := getCmd()

	cmd.SetArgs([]string{"token"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Open(filepath.Join(C.LocalAuthDir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Open(filepath.Join(C.LocalAuthDir, privateKeyFile)); err != nil {
		t.Fatal(err)
	}
}
