package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/capeprivacy/attest/attest"
)

var capeEncryptPrefix = "cape:"

type Options struct {
	URL string
}

type Option func(o *Options)

func WithURL(s string) Option {
	return func(o *Options) {
		o.URL = s
	}
}

func Encrypt(message, username string, options ...Option) (string, error) {
	opts := Options{
		URL: "https://app.capeprivacy.com",
	}

	for _, o := range options {
		o(&opts)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/user/%s/key", opts.URL, username), nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		var r struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return "", fmt.Errorf("something went wrong, status code: %d", resp.StatusCode)
		}

		if r.Error != "" {
			return "", errors.New(r.Error)
		}

		if r.Message != "" {
			return "", errors.New(r.Message)
		}

		return "", fmt.Errorf("something went wrong, status code: %d", resp.StatusCode)
	}

	var r struct {
		AttestationDocument []byte `json:"attestation_document"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", errors.New("error parsing attestation document")
	}

	doc, err := attest.Attest(r.AttestationDocument, nil, nil)
	if err != nil {
		return "", err
	}

	var userData struct {
		Key []byte `json:"key"`
	}

	if err := json.Unmarshal(doc.UserData, &userData); err != nil {
		return "", err
	}

	dataCiphertext, key, err := AESEncrypt([]byte(message))
	if err != nil {
		return "", err
	}

	keyCiphertext, err := RSAEncrypt(key, userData.Key)
	if err != nil {
		return "", err
	}

	ciphertext := base64.StdEncoding.EncodeToString(append(keyCiphertext, dataCiphertext...))
	result := capeEncryptPrefix + ciphertext

	return result, nil
}

func EncryptBytes(keyReq KeyRequest, input []byte) ([]byte, error) {
	capeKey, err := Key(keyReq)
	if err != nil {
		return nil, err
	}

	dataCiphertext, key, err := AESEncrypt(input)
	if err != nil {
		return nil, err
	}

	keyCiphertext, err := RSAEncrypt(key, capeKey)
	if err != nil {
		return nil, err
	}

	keyCiphertext = append(keyCiphertext, dataCiphertext...)

	// Prefix the ciphertext with "cape:"
	output := append([]byte(capeEncryptPrefix), keyCiphertext...)

	return output, nil
}

const AesKeySize = 32

func AESEncrypt(plaintext []byte) ([]byte, []byte, error) {
	key := make([]byte, AesKeySize) // generate a random 32 byte key for AES-256
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

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
