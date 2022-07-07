package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var privateKeyFile = "token.pem"
var publicKeyFile = "token.pub.pem"

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "create a token to execute a cape function",
	RunE:  token,
}

func init() {
	rootCmd.AddCommand(tokenCmd)
}

func token(cmd *cobra.Command, args []string) error {
	publicKey, err := getPublicKey()
	if err != nil {
		// Attempt to generate a key pair if reading public key fails.
		err = generateKeyPair()
		if err != nil {
			return err
		}
		publicKey, err = getPublicKey()
		if err != nil {
			return err
		}
	}

	fmt.Printf("Public key: %p\n", publicKey)
	return nil
}

func getPublicKey() (*rsa.PublicKey, error) {
	publicKeyPEM, err := os.Open(filepath.Join(C.LocalAuthDir, publicKeyFile))
	if err != nil {
		return nil, err
	}
	defer publicKeyPEM.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

func generateKeyPair() error {
	// Ensure the local auth directory is configured.
	err := os.MkdirAll(C.LocalAuthDir, os.ModePerm)
	if err != nil {
		return err
	}

	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey

	// Export private key
	var privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privatePem, err := os.Create(filepath.Join(C.LocalAuthDir, privateKeyFile))
	if err != nil {
		return err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return err
	}

	// Export public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(filepath.Join(C.LocalAuthDir, publicKeyFile))
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}

	return nil
}
