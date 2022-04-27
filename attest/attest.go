package attest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"log"

	"github.com/fxamacker/cbor"
	"github.com/veraison/go-cose"
)

type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
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

func Attest(attestation string) (*AttestationDoc, error) {
	d, err := base64.StdEncoding.DecodeString(attestation)
	if err != nil {
		return nil, err
	}

	// Decode tag content to sign1Message.
	var m sign1Message
	err = cbor.Unmarshal(d, &m)
	if err != nil {
		log.Fatal(err)
	}

	// Create Headers from sign1Message.
	msgHeaders := &cose.Headers{}
	err = msgHeaders.Decode([]interface{}{m.Protected, m.Unprotected})
	if err != nil {
		log.Fatal(err)
	}

	msg := cose.Sign1Message{
		Headers:   msgHeaders,
		Payload:   m.Payload,
		Signature: m.Signature,
	}

	doc := &AttestationDoc{}
	err = cbor.Unmarshal(msg.Payload, doc)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, err
	}

	verifier := cose.Verifier{
		PublicKey: cert.PublicKey.(*ecdsa.PublicKey),
		Alg:       cose.ES384,
	}

	// Verify
	err = msg.Verify([]byte{}, verifier)
	if err != nil {
		return nil, err
	}

	// TODO verify cert chain
	// TODO verify PCRs

	return doc, nil
}
