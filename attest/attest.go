package attest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type AttestationDoc struct {
	ModuleID    string `cbor:"module_id"`
	Timestamp   uint64
	Digest      string
	PCRs        map[int][]byte
	Certificate []byte
	Cabundle    [][]byte
	PublicKey   []byte `cbor:"public_key"`
	// TODO user_data, nonce
}

func createSign1(d []byte) (*cose.Sign1Message, error) {
	var m sign1Message
	err := cbor.Unmarshal(d, &m)
	if err != nil {
		return nil, err
	}
	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			RawProtected:   m.Protected,
			RawUnprotected: m.Unprotected,
		},
		Payload:   m.Payload,
		Signature: m.Signature,
	}
	if err := msg.Headers.UnmarshalFromRaw(); err != nil {
		return nil, err
	}

	return msg, nil
}

func verifySignature(cert *x509.Certificate, msg *cose.Sign1Message) error {
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key must be ecdsa")
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES384, publicKey)
	if err != nil {
		return err
	}

	return msg.Verify([]byte{}, verifier)
}

func verifyCertChain(cert *x509.Certificate, cabundle [][]byte) error {
	pool := x509.NewCertPool()
	for _, certBy := range cabundle {
		cert, err := x509.ParseCertificate(certBy)
		if err != nil {
			return err
		}

		pool.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now().UTC(),
	}

	// TODO we should be doing extra validation somehow against the amazon
	// root cert at https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}

func Attest(attestation string) (*AttestationDoc, error) {
	d, err := base64.StdEncoding.DecodeString(attestation)
	if err != nil {
		return nil, err
	}

	msg, err := createSign1(d)
	if err != nil {
		return nil, err
	}

	doc := &AttestationDoc{}
	err = cbor.Unmarshal(msg.Payload, doc)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, err
	}

	if err := verifySignature(cert, msg); err != nil {
		return nil, err
	}

	if err := verifyCertChain(cert, doc.Cabundle); err != nil {
		return nil, err
	}

	// TODO verify PCRs

	return doc, nil
}
