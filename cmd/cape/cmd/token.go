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
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/spf13/cobra"
)

var privateKeyFile = "token.pem"
var publicKeyFile = "token.pub.pem"

var tokenCmd = &cobra.Command{
	Use:   "token function_id",
	Short: "create a token to execute a cape function",
	RunE:  token,
}

func init() {
	rootCmd.AddCommand(tokenCmd)

	tokenCmd.PersistentFlags().IntP("expires", "e", 3600, "optional time to live (in seconds)")
}

func token(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("you must pass a function ID")
	}

	functionID := args[0]
	expires, err := cmd.Flags().GetInt("expires")
	if err != nil {
		return err
	}

	tokenString, err := Token(functionID, expires)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", tokenString)
	return nil
}

func Token(functionID string, expires int) (string, error) {
	privateKey, err := getOrGeneratePrivateKey()
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Subject:   functionID,
		IssuedAt:  &jwt.NumericDate{Time: time.Now()},
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Second * time.Duration(expires))},
	})
	tokenString, err := token.SignedString(privateKey)

	return tokenString, err
}

func getOrGeneratePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		// Attempt to generate a key pair if reading public key fails.
		err = generateKeyPair()
		if err != nil {
			return nil, err
		}
		privateKey, err = getPrivateKey()
		if err != nil {
			return nil, err
		}
	}
	return privateKey, err
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	keyPEM, err := getPrivateKeyPEM()
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM.Bytes())
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func getPrivateKeyPEM() (*bytes.Buffer, error) {
	privateKeyPEM, err := os.Open(filepath.Join(C.LocalConfigDir, privateKeyFile))
	if err != nil {
		return nil, err
	}
	defer privateKeyPEM.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func generateKeyPair() error {
	// Ensure the local auth directory is configured.
	err := os.MkdirAll(C.LocalConfigDir, os.ModePerm)
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

	privatePem, err := os.Create(filepath.Join(C.LocalConfigDir, privateKeyFile))
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
	publicPem, err := os.Create(filepath.Join(C.LocalConfigDir, publicKeyFile))
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}

	return nil
}
