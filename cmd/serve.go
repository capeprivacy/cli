package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/pbkdf2"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/encryptor"
	"github.com/spf13/cobra"
)

// encryptCmd represents the request command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "test server for cape CLI",
	Run:   serve,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.PersistentFlags().StringP("port", "p", ":9090", "port")
}

type EncryptReq struct {
	Data string `json:"data"`
}

type EncryptRes struct {
	EncryptedData string `json:"encrypted_data"`
}

type RunReq struct {
	EncryptedFunctionData string `json:"function_data"`
	EncryptedInputData    string `json:"input_data"`
	ServerSideEncrypted   bool   `json:"server_side_encrypted"`
}

type RunRes struct {
	Results string `json:"results"`
}

type AttestResponse struct {
	AttestationDoc string `json:"attestation_doc"`
}

type handler struct {
	privateKey   *rsa.PrivateKey
	symmetricKey []byte
	salt         []byte
}

func serve(cmd *cobra.Command, args []string) {
	port, err := cmd.Flags().GetString("port")
	if err != nil {
		panic(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("gen key %s\n", err))
	}

	symmetricKey := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, symmetricKey); err != nil {
		panic(err)
	}

	// salt should really change every time but this is for testing so no big deal
	salt := make([]byte, 8)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}

	h := handler{
		privateKey:   key,
		symmetricKey: symmetricKey,
		salt:         salt,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/attest", http.HandlerFunc(h.attestHandler))
	mux.HandleFunc("/v1/encrypt", http.HandlerFunc(h.encryptHandler))
	mux.HandleFunc("/v1/run", http.HandlerFunc(h.runHandler))

	fmt.Printf("listening on %s\n", port)
	err = http.ListenAndServe(port, mux)
	if err != nil {
		panic(err)
	}
}

func (h handler) attestHandler(rw http.ResponseWriter, r *http.Request) {
	by, err := x509.MarshalPKIXPublicKey(&h.privateKey.PublicKey)
	if err != nil {
		fmt.Printf("x509 marshal pub %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	doc := attest.AttestationDoc{PublicKey: base64.StdEncoding.EncodeToString(by)}
	docBy, err := json.Marshal(doc)
	if err != nil {
		fmt.Printf("json marshal doc %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := AttestResponse{
		AttestationDoc: base64.StdEncoding.EncodeToString(docBy),
	}

	resBy, err := json.Marshal(res)
	if err != nil {
		fmt.Printf("json marshall res %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = rw.Write(resBy)
	if err != nil {
		fmt.Printf("write %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h handler) encryptHandler(rw http.ResponseWriter, r *http.Request) {
	req := &EncryptReq{}

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(req)
	if err != nil {
		fmt.Printf("json decode err %s\n", err)

		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		fmt.Printf("base64 error %s\n", err)

		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	out := &bytes.Buffer{}
	decryptor := encryptor.RSAOAEPEncryptor{Hash: sha256.New(), Label: []byte("cape")}
	err = decryptor.Decrypt(h.privateKey, bytes.NewBuffer(data), out)
	if err != nil {
		fmt.Printf("decrypt rsa error %s\n", err)

		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	secret, decrypted := out.Bytes()[:32], out.Bytes()[32:]

	secret = append(secret, h.symmetricKey...)
	dk := pbkdf2.Key(secret, h.salt, 4096, 32, sha1.New)
	c, err := aes.NewCipher(dk)
	if err != nil {
		fmt.Printf("could not create aes %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Printf("could not create gcm %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("could not read nonce %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	sealedData := gcm.Seal(nonce, nonce, decrypted, nil)

	b64 := base64.StdEncoding.EncodeToString(sealedData)

	res := EncryptRes{EncryptedData: b64}
	jsonBy, err := json.Marshal(res)
	if err != nil {
		fmt.Printf("could not marshal response %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = rw.Write(jsonBy)
	if err != nil {
		fmt.Printf("could not write response %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h handler) rsaDecrypt(decryptor encryptor.RSAOAEPEncryptor, encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		fmt.Printf("base64 error %s\n", err)

		return nil, err
	}

	functionOut := &bytes.Buffer{}
	err = decryptor.Decrypt(h.privateKey, bytes.NewBuffer(data), functionOut)
	if err != nil {
		fmt.Printf("decrypt rsa error %s\n", err)

		return nil, err
	}

	return functionOut.Bytes(), nil
}

func (h handler) aesDecrypt(secret, encrypted []byte) ([]byte, error) {
	newSecretBuf := make([]byte, 0, len(secret)+len(h.symmetricKey))

	newSecretBuf = append(newSecretBuf, secret...)
	newSecretBuf = append(newSecretBuf, h.symmetricKey...)

	dk := pbkdf2.Key(newSecretBuf, h.salt, 4096, 32, sha1.New)

	c, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	nonce, encrypted := encrypted[:nonceSize], encrypted[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, err
}

func (h handler) runHandler(rw http.ResponseWriter, r *http.Request) {
	req := &RunReq{}

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(req)
	if err != nil {
		fmt.Printf("json decode err %s\n", err)

		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	decryptor := encryptor.RSAOAEPEncryptor{Hash: sha256.New(), Label: []byte("cape")}
	functionOut, err := h.rsaDecrypt(decryptor, req.EncryptedFunctionData)
	if err != nil {
		fmt.Printf("rsa decrypt err %s\n", err)

		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	inputOut, err := h.rsaDecrypt(decryptor, req.EncryptedInputData)
	if err != nil {
		fmt.Printf("rsa decrypt err %s\n", err)

		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.ServerSideEncrypted {
		functionSecret, decryptedFunction := functionOut[:32], functionOut[32:]
		_, err = h.aesDecrypt(functionSecret, decryptedFunction)
		if err != nil {
			fmt.Printf("aes decrypt function err %s\n", err)

			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		inputSecret, decryptedInput := inputOut[:32], inputOut[32:]
		_, err = h.aesDecrypt(inputSecret, decryptedInput)
		if err != nil {
			fmt.Printf("aes decrypt input err %s\n", err)

			rw.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// do run here

	res := RunRes{Results: "Decrypted function and data. Results: here are your cool results"}
	jsonBy, err := json.Marshal(res)
	if err != nil {
		fmt.Printf("could not marshal response %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = rw.Write(jsonBy)
	if err != nil {
		fmt.Printf("could not write response %s\n", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}
