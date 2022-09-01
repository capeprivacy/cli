package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt data",
	RunE:  encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().StringP("file", "f", "", "input data file")
}

func encrypt(cmd *cobra.Command, args []string) error {
	input, userError := parseInput(cmd, args)
	if userError != nil {
		return userError
	}

	capeKey, err := getCapeKey()
	if err != nil {
		return err
	}

	dataCiphertext, key, err := AESEncrypt(input)
	if err != nil {
		return err
	}

	keyCiphertext, err := RSAEncrypt(key, capeKey)
	if err != nil {
		return err
	}

	ciphertext := base64.StdEncoding.EncodeToString(append(keyCiphertext, dataCiphertext...))

	capeEncryptPrefix := "cape:"
	result := capeEncryptPrefix + ciphertext

	fmt.Println(result)

	return nil
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

	// TODO: is dst needed?
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

// TODO: Run could use this function.
func parseInput(cmd *cobra.Command, args []string) ([]byte, *UserError) {
	if len(args) > 1 {
		return nil, &UserError{Msg: "you must pass in only one input data (stdin, string or filename)", Err: fmt.Errorf("invalid number of input arguments")}
	}

	var input []byte
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return nil, &UserError{Msg: "error retrieving file flag", Err: err}
	}

	switch {
	case file != "":
		// input file was provided
		input, err = os.ReadFile(file)
		if err != nil {
			return nil, &UserError{Msg: "unable to read data file", Err: err}
		}
	case len(args) == 1:
		// read input from  command line string
		input = []byte(args[0])

	default:
		// read input from stdin
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, cmd.InOrStdin()); err != nil {
			return nil, &UserError{Msg: "unable to read data from stdin", Err: err}
		}
		input = buf.Bytes()
	}

	return input, nil
}
