package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/capeprivacy/cli/attest"
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

type AttestResponse struct {
	AttestationDoc string `json:"attestation_doc"`
}

func serve(cmd *cobra.Command, args []string) {
	port, err := cmd.Flags().GetString("port")
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/attest", func(rw http.ResponseWriter, r *http.Request) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("gen key %s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		by, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
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
	})

	err = http.ListenAndServe(port, mux)
	if err != nil {
		panic(err)
	}
}
