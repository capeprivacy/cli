package cmd

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/encryptor"
	"github.com/spf13/cobra"
)

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

	if len(args) != 1 {
		panic("expected one path to data to encrypt")
	}

	filename := args[0]
	dataBy, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s", err))
	}

	req, err := http.NewRequest("POST", u+"/v1/attest", nil)
	if err != nil {
		panic(fmt.Sprintf("unable to create request %s", err))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(fmt.Sprintf("request failed %s", err))
	}

	if res.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("bad status code %d", res.StatusCode))
	}

	resData := AttestResponse{}

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&resData)
	if err != nil {
		panic(fmt.Sprintf("unable to decode response %s", err))
	}

	doc, err := attest.Attest(resData.AttestationDoc)
	if err != nil {
		panic(fmt.Sprintf("attestation failed %s", err))
	}

	b64, err := base64.StdEncoding.DecodeString(doc.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("base64 decode failed %s", err))
	}

	pub, err := x509.ParsePKIXPublicKey(b64)
	if err != nil {
		panic(fmt.Sprintf("parse x509 failed %s", err))
	}

	encryptedData := new(bytes.Buffer)
	rsaPub := pub.(*rsa.PublicKey)
	encryptor := encryptor.NewRSAOAEPEncryptor(rsaPub, "cape")

	err = encryptor.Encrypt(bytes.NewBuffer(dataBy), encryptedData)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt %s", err))
	}

	outputFilename := fmt.Sprintf("%s.cape", filename)
	err = ioutil.WriteFile(outputFilename, encryptedData.Bytes(), 0644)
	if err != nil {
		panic(fmt.Sprintf("unable to encrypt %s", err))
	}

	fmt.Printf("Successfully encrypted and attested. File written to %s\n", outputFilename)
}
