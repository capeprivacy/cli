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
	Hash          hash.Hash
	Label         []byte
}

func NewRSAOAEPEncryptor(publicKey *rsa.PublicKey, labelStr string) RSAOAEPEncryptor {
	hash := sha256.New()
	max := publicKey.Size() - 2*hash.Size() - 2
	label := []byte(labelStr)
	return RSAOAEPEncryptor{
		PublicKey:     publicKey,
		MaxEncryptLen: max,
		Hash:          hash,
		Label:         label,
	}
}

func (r RSAOAEPEncryptor) Encrypt(read io.Reader, write io.Writer) error {
	buf := make([]byte, r.MaxEncryptLen)
	for {
		n, err := read.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		by, err := rsa.EncryptOAEP(r.Hash, rand.Reader, r.PublicKey, buf[:n], r.Label)
		if err != nil {
			return err
		}

		_, err = write.Write(by)
		if err != nil {
			return err
		}
	}
}

// Decrypt method used mostly for testing only
func (r RSAOAEPEncryptor) Decrypt(privateKey *rsa.PrivateKey, read io.Reader, write io.Writer) error {
	buf := make([]byte, 256)
	for {
		n, err := read.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		by, err := rsa.DecryptOAEP(r.Hash, rand.Reader, privateKey, buf[:n], r.Label)
		if err != nil {
			return err
		}

		_, err = write.Write(by)
		if err != nil {
			return err
		}
	}
}
