package sdk

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/capeprivacy/attest/attest"
	"github.com/capeprivacy/cli/mocks"
)

func TestKeyNotPresent(t *testing.T) {
	dir := t.TempDir()
	file := "testKey.pub.der"
	want := []byte("key")

	// Set up attestation
	userData := AttestationUserData{
		CapeKey: want,
	}
	data, err := json.Marshal(userData)
	if err != nil {
		t.Errorf("unable to set up attestation user data: %s", err)
	}
	doc := attest.AttestationDoc{
		UserData: data,
	}

	verifier := mocks.Verifier{
		VerifyFn: func(attestation []byte, nonce []byte) (*attest.AttestationDoc, error) {
			return &doc, nil
		},
	}

	getProtocolFn = func(ws *websocket.Conn) protocol {
		return mocks.Protocol{}
	}
	defer func() {
		getProtocolFn = getProtocol
	}()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		_, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer s.Close()

	req := KeyRequest{
		ConfigDir:   dir,
		CapeKeyFile: file,
		URL:         wsURL(s.URL),
	}

	got, err := downloadAndSaveKey(req, verifier)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if !bytes.Equal(want, got) {
		t.Fatalf("Key does not match, want: %s, got: %s", want, got)
	}

	savedKey, err := readFile(dir, file)
	if err != nil {
		t.Fatalf("Unexpected error reading file %s", err)
	}

	if !bytes.Equal(want, savedKey) {
		t.Fatalf("Saved key does not match, want: %s, got: %s", want, got)
	}
}

func TestKeyPresent(t *testing.T) {
	dir := t.TempDir()
	file := "testKey.pub.der"

	want := []byte("-----BEGIN PUBLIC KEY-----\nTestKey\n-----END PUBLIC KEY-----")
	err := os.WriteFile(filepath.Join(dir, file), want, os.ModePerm)
	if err != nil {
		t.Fatalf("Unable to setup key file err: %s", err)
	}

	req := KeyRequest{
		ConfigDir:   dir,
		CapeKeyFile: file,
	}

	got, err := Key(req)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if !bytes.Equal(want, got) {
		t.Fatalf("Key retrieved from file does not match, want: %s, got: %s", want, got)
	}
}
