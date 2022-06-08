package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/briandowns/spinner"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/attest"
	czip "github.com/capeprivacy/cli/zip"
)

type DeployRequest struct {
	Nonce     string `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type DeployResponse struct {
	ID string `json:"id"`
}

// deployCmd represents the request command
var deployCmd = &cobra.Command{
	Use:   "deploy [directory | zip file]",
	Short: "deploy a function",
	Long: `Deploy a function to Cape.

This will return an ID that can later be used to invoke the deployed function
with cape run (see cape run -h for details).
`,

	RunE: deploy,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("token", "t", "", "token to use")
	deployCmd.PersistentFlags().StringP("name", "n", "", "a name to give this function (default is the directory name)")
}

func deploy(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("you must specify a directory to upload")
	}

	u, err := cmd.Flags().GetString("url")
	if err != nil {
		return err
	}

	n, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}

	functionInput := args[0]
	name := functionInput
	if n != "" {
		name = n
	}

	dID, err := Deploy(u, name, functionInput)
	if err != nil {
		return err
	}

	fmt.Printf("Success! Deployed function to Cape\nFunction ID ➜ %s\n", dID)

	return nil
}

func Deploy(url string, functionInput string, functionName string) (string, error) {
	file, err := os.Open(functionInput)
	if err != nil {
		return "", fmt.Errorf("unable to read function directory or file: %w", err)
	}

	st, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("unable to read function file or directory: %w", err)
	}
	// There is a linter error for isZip but it should be ignored since it's a conditional variable.
	isZip := false
	if st.IsDir() {
		_, err = file.Readdirnames(1)
		if err != nil {
			return "", fmt.Errorf("please pass in a non-empty directory: %w", err)
		}
	} else {
		// Check if file ends with ".zip" extension.
		fileExtension := filepath.Ext(functionInput)
		if fileExtension != ".zip" {
			return "", fmt.Errorf("expected argument %s to be a zip file or directory", functionInput)
		}
		isZip = true
	}

	err = file.Close()
	if err != nil {
		return "", fmt.Errorf("something went wrong: %w", err)
	}

	var reader io.Reader

	if isZip {
		f, err := os.Open(functionInput)
		if err != nil {
			return "", fmt.Errorf("unable to read function file: %w", err)
		}

		reader = f
	} else {
		buf := new(bytes.Buffer)
		zipRoot := filepath.Base(functionInput)
		w := zip.NewWriter(buf)

		err = filepath.Walk(functionInput, czip.Walker(w, zipRoot))
		if err != nil {
			return "", fmt.Errorf("zipping directory failed: %w", err)
		}

		// Explicitly close now so that the bytes are flushed and
		// available in buf.Bytes() below.
		err = w.Close()
		if err != nil {
			return "", fmt.Errorf("zipping directory failed: %w", err)
		}

		reader = buf
	}

	id, err := doDeploy(url, functionName, reader)
	if err != nil {
		return "", fmt.Errorf("unable to deploy function %w", err)
	}

	return id, nil
}

func doDeploy(url string, name string, reader io.Reader) (string, error) {
	endpoint := fmt.Sprintf("%s/v1/deploy", url)
	s := spinner.New(spinner.CharSets[26], 300*time.Millisecond)
	defer s.Stop()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		s.Stop()
		os.Exit(1)
	}()
	s.Prefix = "Deploying function to Cape "
	s.Start()

	conn, res, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		log.Println("error dialing websocket", res)
		return "", err
	}

	req := DeployRequest{Nonce: getNonce(), AuthToken: getAuthToken()}
	err = conn.WriteJSON(req)
	if err != nil {
		log.Println("error writing deploy request")
		return "", err
	}

	_, docB64, err := conn.ReadMessage()
	if err != nil {
		log.Println("error reading attestation doc")
		return "", err
	}

	_, err = attest.Attest(docB64)
	if err != nil {
		log.Println("error attesting")
		return "", err
	}

	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		log.Println("error getting writer for function")
		return "", err
	}

	_, err = io.Copy(writer, reader)
	if err != nil {
		log.Println("error copying function to websocket")
		return "", err
	}

	resData := DeployResponse{}

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&resData)
	if err != nil {
		return "", fmt.Errorf("unable to decode response %s", err)
	}

	return resData.ID, nil
}

func getNonce() string {
	buf := make([]byte, 16)

	if _, err := rand.Reader.Read(buf); err != nil {
		log.WithError(err).Error("failed to get nonce")
	}

	return base64.StdEncoding.EncodeToString(buf)
}

func getAuthToken() string {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		log.WithError(err).Error("failed to get auth token")
	}

	t := tokenResponse.AccessToken
	if t == "" {
		log.Errorf("empty access token")
	}
	return t
}
