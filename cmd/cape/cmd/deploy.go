package cmd

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	sentinelEntities "github.com/capeprivacy/sentinel/entities"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/pcrs"

	"github.com/capeprivacy/sentinel/runner"

	"github.com/capeprivacy/cli/crypto"

	czip "github.com/capeprivacy/cli/zip"
)

type ErrorMsg struct {
	Error string `json:"error"`
}

type PublicKeyRequest struct {
	FunctionTokenPublicKey string `json:"function_token_pk"`
}

type DeployResponse struct {
	ID string `json:"id"`
}

const storedFunctionMaxBytes = 128_000_000

type OversizeFunctionError struct {
	bytes int64
}

func (e OversizeFunctionError) Error() string {
	return fmt.Sprintf("deployment (%d bytes) exceeds size limit of %d bytes", e.bytes, storedFunctionMaxBytes)
}

// deployCmd represents the request command
var deployCmd = &cobra.Command{
	Use:   "deploy directory | zip_file",
	Short: "Deploy a function",
	Long: `Deploy a function to Cape.

This will return an ID that can later be used to invoke the deployed function
with cape run (see cape run -h for details).
`,

	RunE: deploy,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("name", "n", "", "a name to give this function (default is the directory name)")
	deployCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
}

func deploy(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("you must specify a directory to upload")
	}

	u := C.EnclaveHost
	insecure := C.Insecure

	n, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return fmt.Errorf("error retrieving pcr flags %s", err)
	}

	functionInput := args[0]
	name := functionInput
	if n != "" {
		name = n
	}

	dID, hash, err := Deploy(u, functionInput, name, insecure, pcrSlice)
	if err != nil {
		return err
	}

	log.Infof("Success! Deployed function to Cape\nFunction ID ➜ %s\nFunction Hash ➜ %x\n", dID, hash)

	return nil
}

func Deploy(url string, functionInput string, functionName string, insecure bool, pcrSlice []string) (string, []byte, error) {
	file, err := os.Open(functionInput)
	if err != nil {
		return "", nil, fmt.Errorf("unable to read function directory or file: %w", err)
	}

	st, err := file.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("unable to read function file or directory: %w", err)
	}

	isZip := false
	var fileSize int64
	if st.IsDir() {
		_, err = file.Readdirnames(1)
		if err != nil {
			return "", nil, fmt.Errorf("please pass in a non-empty directory: %w", err)
		}
		fileSize, err = dirSize(functionInput)
		if err != nil {
			return "", nil, fmt.Errorf("error reading file size: %w", err)
		}
	} else {
		// Check if file ends with ".zip" extension.
		fileExtension := filepath.Ext(functionInput)
		if fileExtension != ".zip" {
			return "", nil, fmt.Errorf("expected argument %s to be a zip file or directory", functionInput)
		}
		isZip = true
		fileSize = st.Size()
		log.Warning("Deploying from zip file. Uncompressed file may exceed deployment size limit.")
	}

	log.Debugf("Deployment size: %d bytes", fileSize)
	if fileSize > storedFunctionMaxBytes {
		err = OversizeFunctionError{bytes: fileSize}
		log.Error(err.Error())
		return "", nil, err
	}

	err = file.Close()
	if err != nil {
		return "", nil, fmt.Errorf("something went wrong: %w", err)
	}

	var reader io.Reader

	if isZip {
		f, err := os.Open(functionInput)
		if err != nil {
			return "", nil, fmt.Errorf("unable to read function file: %w", err)
		}

		reader = f
	} else {
		buf, err := czip.Create(functionInput)
		if err != nil {
			return "", nil, err
		}

		reader = bytes.NewBuffer(buf)
	}

	id, hash, err := doDeploy(url, functionName, reader, insecure, pcrSlice)
	if err != nil {
		return "", nil, fmt.Errorf("unable to deploy function: %w", err)
	}

	return id, hash, nil
}

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func doDeploy(url string, name string, reader io.Reader, insecure bool, pcrSlice []string) (string, []byte, error) {
	endpoint := fmt.Sprintf("%s/v1/deploy", url)

	log.Info("Deploying function to Cape ...")

	conn, res, err := websocketDial(endpoint, insecure)
	if err != nil {
		log.Error("error dialing websocket: ", err)
		// This check is necessary because we don't necessarily return an http response from sentinel.
		// Http error code and message is returned if network routing fails.
		if res != nil {
			var e ErrorMsg
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				return "", nil, err
			}
			res.Body.Close()
			return "", nil, fmt.Errorf("error code: %d, reason: %s", res.StatusCode, e.Error)
		}
		return "", nil, err
	}
	defer conn.Close()

	p := runner.Protocol{Websocket: conn}

	nonce, err := crypto.GetNonce()
	if err != nil {
		return "", nil, err
	}

	token, err := getAuthToken()
	if err != nil {
		return "", nil, err
	}

	functionTokenPublicKey, err := getFunctionTokenPublicKey()
	if err != nil {
		return "", nil, err
	}

	req := sentinelEntities.StartRequest{Nonce: []byte(nonce), AuthToken: token}
	log.Debug("\n> Sending Nonce and Auth Token")
	if err := p.WriteStart(req); err != nil {
		log.Error("error writing deploy request")
		return "", nil, err
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Error("error reading attestation doc")
		return "", nil, err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return "", nil, err
	}

	log.Debug("< Attestation document")
	doc, _, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Error("error attesting")
		return "", nil, err
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(pcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return "", nil, err
	}

	hasher := sha256.New()
	// tReader is used to stream data to the hasher function.
	tReader := io.TeeReader(reader, hasher)
	plaintext, err := io.ReadAll(tReader)
	if err != nil {
		log.Error("error reading plaintext function")
		return "", nil, err
	}

	// Print out the hash to the user.
	hash := hasher.Sum(nil)
	ciphertext, err := crypto.LocalEncrypt(*doc, plaintext)
	if err != nil {
		log.Error("error encrypting function")
		return "", nil, err
	}

	log.Debug("\n> Sending Public Key")
	if err := p.WriteFunctionPublicKey(functionTokenPublicKey); err != nil {
		log.Error("error sending public key")
		return "", nil, err
	}

	log.Debug("\n> Deploying Encrypted Function")
	err = writeFunction(conn, bytes.NewBuffer(ciphertext))
	if err != nil {
		return "", nil, err
	}

	log.Debug("* Waiting for deploy response...")

	resData, err := p.ReadDeploymentResults()
	if err != nil {
		return "", nil, err
	}
	log.Debugf("< Received Deploy Response %v", resData)

	return resData.ID, hash, nil
}

func websocketDial(url string, insecure bool) (*websocket.Conn, *http.Response, error) {
	if insecure {
		websocket.DefaultDialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	str := fmt.Sprintf("* Dialing %s", url)
	if insecure {
		str += " (insecure)"
	}

	log.Debug(str)
	c, r, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return nil, r, err
	}

	log.Debugf("* Websocket connection established")
	return c, r, nil
}

func writeFunction(conn *websocket.Conn, reader io.Reader) error {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		log.Errorf("error getting writer for function: %v", err)
		return err
	}
	defer writer.Close()

	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}

	return nil
}

func getAuthToken() (string, error) {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		return "", fmt.Errorf("failed to get auth token (did you run 'cape login'?): %v", err)
	}

	t := tokenResponse.AccessToken
	if t == "" {
		return "", fmt.Errorf("empty access token (did you run 'cape login'?): %v", err)
	}

	log.Debug("* Retrieved Auth Token")

	return t, nil
}

func getOrGeneratePublicKey() (*rsa.PublicKey, error) {
	publicKey, err := getPublicKey()
	if err != nil {
		// Attempt to generate a key pair if reading public key fails.
		err = generateKeyPair()
		if err != nil {
			return nil, nil
		}
		publicKey, err = getPublicKey()
		if err != nil {
			return nil, nil
		}
	}
	return publicKey, err
}

func getPublicKey() (*rsa.PublicKey, error) {
	keyPEM, err := getPublicKeyPEM()
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM.Bytes())
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

func getPublicKeyPEM() (*bytes.Buffer, error) {
	publicKeyPEM, err := os.Open(filepath.Join(C.LocalConfigDir, publicKeyFile))
	if err != nil {
		return nil, err
	}
	defer publicKeyPEM.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func getFunctionTokenPublicKey() (string, error) {
	_, err := getOrGeneratePublicKey()
	if err != nil {
		return "", err
	}

	// Read the raw PEM.
	pem, err := getPublicKeyPEM()
	if err != nil {
		return "", err
	}

	return pem.String(), nil
}
