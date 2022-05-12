package crypto

import (
	"bytes"
	"fmt"

	"github.com/capeprivacy/cli/attest"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
)

func LocalEncrypt(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) {
	buf := bytes.NewBuffer(doc.PublicKey)
	reader := keyset.NewBinaryReader(buf)
	khPub, err := keyset.ReadWithNoSecrets(reader)
	if err != nil {
		return nil, fmt.Errorf("read pubic key %s", err)
	}

	encrypt, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypt.Encrypt(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	return ciphertext, nil
}
