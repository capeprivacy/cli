package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/veraison/go-cose"
)

func TestCreateSign1(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES384, k)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = []byte("hello world")
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)

	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	by, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	newMsg, err := createSign1(by)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(newMsg.Payload, msg.Payload) {
		t.Fatalf("expected %s got %s", base64.StdEncoding.EncodeToString(newMsg.Payload),
			base64.StdEncoding.EncodeToString(msg.Payload))
	}
}

func TestVerifySig(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := &x509.Certificate{
		PublicKey: &k.PublicKey,
	}

	signer, err := cose.NewSigner(cose.AlgorithmES384, k)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = []byte("hello world")
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)

	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	err = verifySignature(cert, msg)
	if err != nil {
		t.Fatal(err)
	}
}

func newCertAndCabundle(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	parent := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			Country:      []string{"Earth"},
			Organization: []string{"Mother Nature"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	parentBy, err := x509.CreateCertificate(rand.Reader, parent, parent, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			Country:      []string{"Earth"},
			Organization: []string{"Mother Nature"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	by, err := x509.CreateCertificate(rand.Reader, template, parent, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(by)
	if err != nil {
		t.Fatal(err)
	}

	return k, cert, parentBy
}

func TestVerifyCertChains(t *testing.T) {
	_, cert, parent := newCertAndCabundle(t)

	err := verifyCertChain(cert, [][]byte{parent})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAttest(t *testing.T) {
	privateKey, cert, parent := newCertAndCabundle(t)

	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	khPublic, err := khPriv.Public()
	if err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	writer := keyset.NewBinaryWriter(buf)
	err = khPublic.WriteWithNoSecrets(writer)
	if err != nil {
		t.Fatal(err)
	}

	doc := &AttestationDoc{
		ModuleID:    "my-module",
		Timestamp:   uint64(time.Now().Second()),
		Digest:      "abcd",
		PCRs:        map[int][]byte{0: []byte("pcrpcrpcr")},
		Certificate: cert.Raw,
		Cabundle:    [][]byte{parent},
		PublicKey:   buf.Bytes(),
	}

	by, err := cbor.Marshal(doc, cbor.EncOptions{})
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES384, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = by
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)

	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	sign1, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	newDoc, err := Attest(base64.StdEncoding.EncodeToString(sign1))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(doc, newDoc) {
		t.Fatalf("expected %v got %v", doc, newDoc)
	}
}
