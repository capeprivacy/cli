package cli

import "github.com/capeprivacy/attest/attest"

type Checksums struct {
	Input    []byte `json:"input"`
	Function []byte `json:"function"`
	Output   []byte `json:"output"`
}

type RunResult struct {
	// TODO -- Remove type??
	Type          string    `json:"type"`
	Message       []byte    `json:"message"`
	Checksums     Checksums `json:"checksums"`
	SignedResults []byte    `json:"signed_checksums"`

	DecodedAttestationDocument *attest.AttestationDoc `json:"decoded_attestation_document"`
	RawAttestationDocument     []byte                 `json:"raw_attestation_document"`
}
