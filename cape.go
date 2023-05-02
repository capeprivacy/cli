package cli

import (
	"encoding/json"
	"io"
	"os"

	"golang.org/x/oauth2"

	"github.com/capeprivacy/attest/attest"
)

type Checksums struct {
	Input    []byte `json:"input"`
	Function []byte `json:"function"`
	Output   []byte `json:"output"`
}

type RunResult struct {
	Type            string    `json:"type"`
	Message         []byte    `json:"message"`
	Checksums       Checksums `json:"checksums"`
	SignedChecksums []byte    `json:"signed_checksums"`

	DecodedAttestationDocument *attest.AttestationDoc `json:"decoded_attestation_document"`
	RawAttestationDocument     []byte                 `json:"raw_attestation_document"`
}

func TokenFromFile(path string) (*oauth2.Token, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return TokenFromReader(f)
}

func TokenFromReader(r io.Reader) (*oauth2.Token, error) {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var tok *oauth2.Token
	if err := json.Unmarshal(bytes, &tok); err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return nil, err
	}

	return tok.WithExtra(raw), nil
}
