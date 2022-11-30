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
	"os"
	"path"
	"testing"
)

func TestEncrypt(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(path.Join(t.TempDir(), "capekey.pub.der"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write(der)
	if err != nil {
		t.Fatal(err)
	}

	f.Close()

	ciphertext, err := Encrypt(KeyRequest{
		CapeKeyFile: f.Name(),
	}, []byte("hi my name is"))
	if err != nil {
		t.Fatal(err)
	}

	if expectedLen := 401; len(ciphertext) != expectedLen {
		t.Fatalf("encrypted message length must equal %d, it equals %d", expectedLen, len(ciphertext))
	}

	decCipherText, err := base64.StdEncoding.DecodeString(ciphertext[5:])
	if err != nil {
		t.Fatal(err)
	}

	rsaKeyCipherText := decCipherText[:256]
	rsaKeyPlainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k, rsaKeyCipherText, nil)
	if err != nil {
		t.Fatal(err)
	}

	aesCipherText := decCipherText[256:]

	block, err := aes.NewCipher(rsaKeyPlainText)
	if err != nil {
		t.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := gcm.Open(nil, aesCipherText[:gcm.NonceSize()], aesCipherText[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatal(err)
	}

	expectedPlaintext := "hi my name is"
	if string(plaintext) != expectedPlaintext {
		fmt.Println(string(plaintext))
		t.Fatalf("expected plaintext to equal %s got %s", expectedPlaintext, string(plaintext))
	}
}
