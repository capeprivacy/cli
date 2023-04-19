package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigNoArgs(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"config"})

	want := "Here are the configurable options"

	if err := cmd.Execute(); err != nil {
		t.Fatalf("received unexpected error: %s", err)
	}

	if got, want := stderr.String(), ""; got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("stdout did not contain configurable options")
	}
}

func TestConfigFileNotExist(t *testing.T) {
	dir, err := os.MkdirTemp("", "cfgTest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cfgFile := filepath.Join(dir, "presets.json")
	os.Setenv("LOCAL_PRESETS_FILE", cfgFile)
	defer os.Unsetenv("LOCAL_PRESETS_FILE")

	cmd, _, stderr := getCmd()
	cmd.SetArgs([]string{"config", "dev_disable_ssl", "true"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("received unexpected error: %s", err)
	}

	if got, want := stderr.String(), ""; got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	b, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	cfg := struct {
		DevDisableSSL string `json:"dev_disable_ssl"`
	}{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("function stored invalid json")
	}

	// Check new value has been added
	if got, want := cfg.DevDisableSSL, "true"; got != want {
		t.Errorf("didn't get expected value got: %s, want: %s", got, want)
	}
}

func TestConfigFileExists(t *testing.T) {
	f, err := os.CreateTemp("", "cfgTest")
	if err != nil {
		t.Errorf("unable to create temp config file: %s", err)
	}
	defer os.Remove(f.Name())
	os.Setenv("LOCAL_PRESETS_FILE", f.Name())
	defer os.Unsetenv("LOCAL_PRESETS_FILE")

	err = os.WriteFile(
		f.Name(),
		[]byte(`{"auth_host":"www.auth.com"}`),
		0600)
	if err != nil {
		t.Errorf("unable to set up config file: %s", err)
	}

	cmd, _, stderr := getCmd()
	cmd.SetArgs([]string{"config", "dev_disable_ssl", "true"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("received unexpected error: %s", err)
	}

	if got, want := stderr.String(), ""; got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	cfg := struct {
		AuthHost      string `json:"auth_host"`
		DevDisableSSL string `json:"dev_disable_ssl"`
	}{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("function stored invalid json")
	}

	// Check existing value isn't overwritten
	if got, want := cfg.AuthHost, "www.auth.com"; got != want {
		t.Errorf("didn't get expected value got: %s, want: %s", got, want)
	}

	// Check new value has been added
	if got, want := cfg.DevDisableSSL, "true"; got != want {
		t.Errorf("didn't get expected value got: %s, want: %s", got, want)
	}
}
