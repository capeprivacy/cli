package sdk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Tests may fail if run on Windows, unix permissioning

func TestPersistFile(t *testing.T) {
	dir := t.TempDir()
	filename := "testFile"
	path := filepath.Join(dir, filename)
	data := []byte("Hello, this is a test")

	err := PersistFile(dir, filename, data)
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, data) {
		t.Fatal("Incorrect data persisted to file")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatal("Incorrect permissions on file")
	}
}

func TestPersistFileExists(t *testing.T) {
	dir := t.TempDir()
	filename := "testFile"
	path := filepath.Join(dir, filename)
	data := []byte("Hello, this is a test")

	// Create file beforehand
	err := os.WriteFile(path, []byte("Badly permissioned file"), 0777)
	if err != nil {
		t.Fatalf("error setting up file for test: %s", err)
	}

	err = PersistFile(dir, filename, data)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatal("Incorrect permissions on file")
	}
}

func TestPersistDirExists(t *testing.T) {
	// Creates directory beforehand
	dir := t.TempDir()

	err := PersistFile(dir, "testFile", []byte("Hello, this is a test"))
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o700 {
		t.Fatal("Incorrect permissions on directory")
	}
}
