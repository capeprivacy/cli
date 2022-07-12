package crypto

import (
	"fmt"

	"crypto/rand"
	"github.com/cloudflare/circl/hpke"

	"github.com/capeprivacy/cli/attest"
)

func LocalEncrypt(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) {

	kemID := hpke.KEM_X25519_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_ChaCha20Poly1305
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	kemPublicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(doc.PublicKey)
  if err != nil {
    fmt.Println(err)
  }

	sender, err := suite.NewSender(kemPublicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	encapsulatedKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	payload := append(encapsulatedKey, ciphertext...)

	return payload, nil
}
