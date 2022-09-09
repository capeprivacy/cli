package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
)

func Encrypt(keyReq KeyRequest, input []byte) (string, error) {
	capeKey, err := Key(keyReq)
	if err != nil {
		return "", err
	}

	dataCiphertext, key, err := AESEncrypt(input)
	if err != nil {
		return "", err
	}

	keyCiphertext, err := RSAEncrypt(key, capeKey)
	if err != nil {
		return "", err
	}

	ciphertext := base64.StdEncoding.EncodeToString(append(keyCiphertext, dataCiphertext...))

	capeEncryptPrefix := "cape:"
	result := capeEncryptPrefix + ciphertext

	return result, nil
}

func AESEncrypt(plaintext []byte) ([]byte, []byte, error) {
	key := make([]byte, 32) // generate a random 32 byte key for AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Including the nonce in the first parameter embeds it as a prefix in the ciphertext. This is so the nonce doesn't need to be returned and stored.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, key, nil
}

func RSAEncrypt(plaintext []byte, publicKey []byte) ([]byte, error) {
	pubAny, err := x509.ParsePKIXPublicKey(publicKey)

	if err != nil {
		return nil, err
	}

	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unknown public key type")
	}

	hash := sha256.New()
	salt := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(hash, salt, pub, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
