package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/capeprivacy/cli/attest"
	sentinelEntities "github.com/capeprivacy/sentinel/entities"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/sentinel/runner"

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

// deployCmd represents the request command
var deployCmd = &cobra.Command{
	Use:   "deploy directory | zip_file",
	Short: "deploy a function",
	Long: `Deploy a function to Cape.

This will return an ID that can later be used to invoke the deployed function
with cape run (see cape run -h for details).
`,

	RunE: deploy,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("name", "n", "", "a name to give this function (default is the directory name)")
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

	functionInput := args[0]
	name := functionInput
	if n != "" {
		name = n
	}

	dID, hash, err := Deploy(u, name, functionInput, insecure)
	if err != nil {
		return err
	}

	log.Infof("Success! Deployed function to Cape\nFunction ID ➜ %s\nFunction Hash ➜ %x\n", dID, hash)

	return nil
}

func Deploy(url string, functionInput string, functionName string, insecure bool) (string, []byte, error) {
	file, err := os.Open(functionInput)
	if err != nil {
		return "", nil, fmt.Errorf("unable to read function directory or file: %w", err)
	}

	st, err := file.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("unable to read function file or directory: %w", err)
	}

	isZip := false
	if st.IsDir() {
		_, err = file.Readdirnames(1)
		if err != nil {
			return "", nil, fmt.Errorf("please pass in a non-empty directory: %w", err)
		}
	} else {
		// Check if file ends with ".zip" extension.
		fileExtension := filepath.Ext(functionInput)
		if fileExtension != ".zip" {
			return "", nil, fmt.Errorf("expected argument %s to be a zip file or directory", functionInput)
		}
		isZip = true
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
		buf := new(bytes.Buffer)
		zipRoot := filepath.Base(functionInput)
		w := zip.NewWriter(buf)

		err = filepath.Walk(functionInput, czip.Walker(w, zipRoot))
		if err != nil {
			return "", nil, fmt.Errorf("zipping directory failed: %w", err)
		}

		// Explicitly close now so that the bytes are flushed and
		// available in buf.Bytes() below.
		err = w.Close()
		if err != nil {
			return "", nil, fmt.Errorf("zipping directory failed: %w", err)
		}

		reader = buf
	}

	id, hash, err := doDeploy(url, functionName, reader, insecure)
	if err != nil {
		return "", nil, fmt.Errorf("unable to deploy function: %w", err)
	}

	return id, hash, nil
}

func doDeploy(url string, name string, reader io.Reader, insecure bool) (string, []byte, error) {
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
		return nil, nil, err
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

	return strings.ReplaceAll(pem.String(), "\n", ""), nil
}
