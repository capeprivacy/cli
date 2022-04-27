package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/capeprivacy/cli/attest"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/spf13/cobra"
)

type EncryptedData struct {
	Data   []byte
	Secret []byte
}

func (e EncryptedData) MarshalJSON() ([]byte, error) {
	d := struct {
		Data   string `json:"data"`
		Secret string `json:"secret"`
	}{
		Data:   base64.StdEncoding.EncodeToString(e.Data),
		Secret: base64.StdEncoding.EncodeToString(e.Secret),
	}

	return json.Marshal(d)
}

func (e *EncryptedData) UnmarshalJSON(by []byte) error {
	d := struct {
		Data   string `json:"data"`
		Secret string `json:"secret"`
	}{}

	err := json.Unmarshal(by, &d)
	if err != nil {
		return err
	}

	data, err := base64.StdEncoding.DecodeString(d.Data)
	if err != nil {
		return err
	}

	e.Data = data

	secret, err := base64.StdEncoding.DecodeString(d.Secret)
	if err != nil {
		return err
	}

	e.Secret = secret

	return nil
}

// encryptCmd represents the request command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypts function or data",
	Run:   encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().StringP("token", "t", "", "token to use")
}

func encrypt(cmd *cobra.Command, args []string) {
	u, err := cmd.Flags().GetString("url")
	if err != nil {
		panic(err)
	}

	secretBuf := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, secretBuf)
	if err != nil {
		panic(err)
	}

	if len(args) != 1 {
		panic("expected one path to data to encrypt")
	}

	filename := args[0]
	dataBy, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	doc, err := doAttest(u)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	dataBy = append(secretBuf, dataBy...)
	encryptedData, err := doLocalEncrypt(*doc, dataBy)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt data %s", err))
	}

	remoteEncryptedData, err := doEnclaveEncrypt(u, encryptedData)
	if err != nil {
		panic(fmt.Sprintf("unable to remote encrypt data %s", err))
	}

	out := EncryptedData{
		Data:   remoteEncryptedData,
		Secret: secretBuf,
	}

	outputFilename := fmt.Sprintf("%s.cape", filename)
	f, err := os.Create(outputFilename)
	if err != nil {
		panic(fmt.Sprintf("unable to create output file %s", err))
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	err = enc.Encode(out)
	if err != nil {
		panic(fmt.Sprintf("unable to encode output %s", err))
	}

	fmt.Printf("Successfully encrypted and attested. File written to %s. Your secret is %s\n",
		outputFilename, base64.StdEncoding.EncodeToString(secretBuf))
}

func doAttest(URL string) (*attest.AttestationDoc, error) {
	req, err := http.NewRequest("POST", URL+"/v1/attest", nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed %s", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code %d", res.StatusCode)
	}

	resData := AttestResponse{}

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&resData)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response %s", err)
	}

	doc, err := attest.Attest(resData.AttestationDoc)
	if err != nil {
		return nil, fmt.Errorf("attestation failed %s", err)
	}

	return doc, nil
}

func doLocalEncrypt(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) {
	b64, err := base64.StdEncoding.DecodeString(doc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed %s", err)
	}

	buf := bytes.NewBuffer(b64)
	reader := keyset.NewBinaryReader(buf)
	khPub, err := keyset.ReadWithNoSecrets(reader)
	if err != nil {
		return nil, fmt.Errorf("read pubic key %s", err)
	}

	encrypt, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypt.Encrypt(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt %s", err)
	}

	return ciphertext, nil
}

func doEnclaveEncrypt(URL string, localEncryptedData []byte) ([]byte, error) {
	b64 := base64.StdEncoding.EncodeToString(localEncryptedData)

	reqData := EncryptReq{Data: b64}
	jsonBy, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("unable to json encode %s", err)
	}

	req, err := http.NewRequest("POST", URL+"/v1/encrypt", bytes.NewBuffer(jsonBy))
	if err != nil {
		return nil, fmt.Errorf("unable to create request %s", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed %s", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code %d", res.StatusCode)
	}

	resData := &EncryptRes{}
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(resData)
	if err != nil {
		return nil, fmt.Errorf("unable to decode res %s", err)
	}

	return base64.StdEncoding.DecodeString(resData.EncryptedData)
}
