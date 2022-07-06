package crypto

import (
	"bytes"
	"fmt"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
)

func LocalEncrypt(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) {
	log.Debug("* Encrypting inputs with enclave public key")
	log.Debugf("\t* Loading public key")
	buf := bytes.NewBuffer(doc.PublicKey)
	reader := keyset.NewBinaryReader(buf)
	khPub, err := keyset.ReadWithNoSecrets(reader)
	if err != nil {
		return nil, fmt.Errorf("read pubic key %s", err)
	}

	log.Debug("\t* Initializing hybrid encryption")
	encrypt, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, err
	}

	log.Debug("\t* Encrypting input")
	ciphertext, err := encrypt.Encrypt(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	log.Debug("\t* Ciphertext generated")
	return ciphertext, nil
}
