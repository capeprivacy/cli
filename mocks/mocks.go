package mocks

import "github.com/capeprivacy/attest/attest"

type MockVerifier struct {
	VerifyFn func(attestation []byte, nonce []byte) (*attest.AttestationDoc, error)
}

func (m MockVerifier) Verify(attestation []byte, nonce []byte) (*attest.AttestationDoc, error) {
	return m.VerifyFn(attestation, nonce)
}
