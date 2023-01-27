package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/attest/attest"
)

const (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_ChaCha20Poly1305
)

func LogHPKE() {
	log.Debugf("\t** Key Encapsulation Mechanism (KEM): ")
	switch kemID {
	case hpke.KEM_X25519_HKDF_SHA256:
		log.Debugf("\t*** X25519 Diffie-Hellman function")
	case hpke.KEM_P256_HKDF_SHA256:
		fallthrough
	case hpke.KEM_P384_HKDF_SHA384:
		fallthrough
	case hpke.KEM_P521_HKDF_SHA512:
		fallthrough
	case hpke.KEM_X448_HKDF_SHA512:
		fallthrough
	default:
		log.Debugf("\t*** Unknown")
	}

	log.Debugf("\t** Key Derivation Function (KDF): ")
	switch kdfID {
	case hpke.KDF_HKDF_SHA256:
		log.Debugf("\t*** HMAC-based key derivation function (HKDF) with SHA-256")
	case hpke.KDF_HKDF_SHA384:
		fallthrough
	case hpke.KDF_HKDF_SHA512:
		fallthrough
	default:
		log.Debugf("\t*** Unknown")
	}

	log.Debugf("\t** Authenticated Encryption with Additional Data (AEAD): ")
	switch aeadID {
	case hpke.AEAD_ChaCha20Poly1305:
		log.Debugf("\t*** ChaCha20 stream cipher and Poly1305 MAC")
	case hpke.AEAD_AES128GCM:
		fallthrough
	case hpke.AEAD_AES256GCM:
		fallthrough
	default:
		log.Debugf("\t*** Unknown")
	}
}

func LocalEncrypt(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) {
	log.Debug("\n* Encrypting Inputs")
	log.Debugf("\t* Loading Public Key from Attestation Document")
	publicKey := doc.PublicKey
	log.Debugf("\t** Retrieved Public Key: %x", publicKey)

	log.Debugf("\t* Configuring Hybrid Public Key Encryption (HPKE): ")
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	LogHPKE()

	kemPublicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	sender, err := suite.NewSender(kemPublicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	log.Debugf("\t* Generating Encapsulated Key")
	log.Debugf("\t** Generating random bytes...")
	encapsulatedKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}
	log.Debugf("\t** Encapsulated Key: %x", encapsulatedKey)

	log.Debugf("\t* Generating Ciphertext")
	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}
	log.Debugf("\t** Complete.")

	return append(encapsulatedKey, ciphertext...), nil
}
