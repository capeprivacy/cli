package encryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"io"
)

type RSAOAEPEncryptor struct {
	PublicKey     *rsa.PublicKey
	MaxEncryptLen int
	hash          hash.Hash
	label         []byte
}

func NewRSAOAEPEncryptor(publicKey *rsa.PublicKey, labelStr string) RSAOAEPEncryptor {
	hash := sha256.New()
	max := publicKey.Size() - 2*hash.Size() - 2
	label := []byte(labelStr)
	return RSAOAEPEncryptor{
		PublicKey:     publicKey,
		MaxEncryptLen: max,
		hash:          hash,
		label:         label,
	}
}

func (r RSAOAEPEncryptor) Encrypt(read io.Reader, write io.Writer) error {
	buf := make([]byte, r.MaxEncryptLen)
	for {
		_, err := read.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		by, err := rsa.EncryptOAEP(r.hash, rand.Reader, r.PublicKey, buf, r.label)
		if err != nil {
			return err
		}

		_, err = write.Write(by)
		if err != nil {
			return err
		}
	}
}
