package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToken(t *testing.T) {
	cmd, _, _ := getCmd()

	cmd.SetArgs([]string{"token", "5gWto31CNOTI"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Open(filepath.Join(C.LocalConfigDir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Open(filepath.Join(C.LocalConfigDir, privateKeyFile)); err != nil {
		t.Fatal(err)
	}
}
