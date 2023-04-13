package mocks

import (
	"github.com/capeprivacy/attest/attest"
	"github.com/capeprivacy/cli"
	"github.com/capeprivacy/cli/entities"
)

type Verifier struct {
	VerifyFn func(attestation []byte, nonce []byte) (*attest.AttestationDoc, error)
}

func (v Verifier) Verify(attestation []byte, nonce []byte) (*attest.AttestationDoc, error) {
	if v.VerifyFn != nil {
		return v.VerifyFn(attestation, nonce)
	}
	return &attest.AttestationDoc{}, nil
}

type Protocol struct {
	WriteStartFn            func(req entities.StartRequest) error
	ReadAttestationDocFn    func() ([]byte, error)
	ReadRunResultsFn        func() (*cli.RunResult, error)
	WriteBinaryFn           func(b []byte) error
	WriteFunctionInfoFn     func(name string, public bool) error
	ReadDeploymentResultsFn func() (*entities.SetDeploymentIDRequest, error)
}

func (p Protocol) WriteStart(req entities.StartRequest) error {
	if p.WriteStartFn != nil {
		return p.WriteStartFn(req)
	}
	return nil
}

func (p Protocol) ReadAttestationDoc() ([]byte, error) {
	if p.ReadAttestationDocFn != nil {
		return p.ReadAttestationDocFn()
	}
	return []byte{}, nil
}

func (p Protocol) ReadRunResults() (*cli.RunResult, error) {
	if p.ReadRunResultsFn != nil {
		return p.ReadRunResultsFn()
	}
	return &cli.RunResult{}, nil
}

func (p Protocol) WriteBinary(b []byte) error {
	if p.WriteBinaryFn != nil {
		return p.WriteBinaryFn(b)
	}
	return nil
}

func (p Protocol) WriteFunctionInfo(name string, public bool) error {
	if p.WriteFunctionInfoFn != nil {
		return p.WriteFunctionInfoFn(name, public)
	}
	return nil
}

func (p Protocol) ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error) {
	if p.ReadDeploymentResultsFn != nil {
		return p.ReadDeploymentResultsFn()
	}
	return &entities.SetDeploymentIDRequest{}, nil
}
