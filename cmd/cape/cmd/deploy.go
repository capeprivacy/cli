package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/render"
	"github.com/capeprivacy/cli/sdk"
	czip "github.com/capeprivacy/cli/zip"
)

type PublicKeyRequest struct {
	FunctionTokenPublicKey string `json:"function_token_pk"`
}

type DeployResponse struct {
	ID string `json:"id"`
}

const storedFunctionMaxBytes = 1_000_000_000

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

	RunE: func(cmd *cobra.Command, args []string) error {
		err := deploy(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("name", "n", "", "a name to give this function (default is the directory name)")
	deployCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
	deployCmd.PersistentFlags().BoolP("public", "", false, "make the function public (anyone can run it)")

	registerTemplate(deployCmd.Name(), deployTmpl)
}

func deploy(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return UserError{Msg: "you must specify a directory to upload", Err: fmt.Errorf("invalid number of input arguments")}
	}

	u := C.EnclaveHost
	insecure := C.Insecure

	n, err := cmd.Flags().GetString("name")
	if err != nil {
		return UserError{Msg: "name not specified correctly", Err: err}
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	public, err := cmd.Flags().GetBool("public")
	if err != nil {
		return UserError{Msg: "error retrieving public flag", Err: err}
	}

	functionInput := args[0]
	name := getName(functionInput, n)

	dID, checksum, err := doDeploy(u, functionInput, name, insecure, pcrSlice, public)
	if err != nil {
		return err
	}

	username, err := getUsername()
	if err != nil {
		return err
	}

	// older tokens might not have a username, in that case, we just won't tell them the function alias
	functionName := ""
	if username != "" {
		functionName = fmt.Sprintf("%s/%s", username, name)
	}

	output := struct {
		ID           string `json:"function_id"`
		Checksum     string `json:"function_checksum"`
		FunctionName string `json:"function_name,omitempty"`
	}{
		ID:           dID,
		Checksum:     fmt.Sprintf("%x", checksum),
		FunctionName: functionName,
	}

	return render.Ctx(cmd.Context()).Render(cmd.OutOrStdout(), output)
}

func getName(functionInput string, nameFlag string) string {
	if nameFlag != "" {
		return nameFlag
	}
	return strings.Split(filepath.Base(functionInput), ".")[0]
}

func doDeploy(url string, functionInput string, functionName string, insecure bool, pcrSlice []string, public bool) (string, []byte, error) {
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
		zSize, err := zipSize(functionInput)
		if err != nil {
			return "", nil, err
		}

		fileSize = int64(zSize)
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

	token, err := getAuthToken()
	if err != nil {
		return "", nil, err
	}

	// Public functions do not include a public key.
	//	Public keys are used for function tokens.
	functionTokenPublicKey := ""
	if !public {
		functionTokenPublicKey, err = getFunctionTokenPublicKey()
		if err != nil {
			return "", nil, err
		}
	}

	keyReq, err := GetKeyRequest(pcrSlice)
	if err != nil {
		return "", nil, err
	}

	id, checksum, err := sdk.Deploy(sdk.DeployRequest{
		URL:                    url,
		Name:                   functionName,
		Reader:                 reader,
		Insecure:               insecure,
		PcrSlice:               pcrSlice,
		FunctionTokenPublicKey: functionTokenPublicKey,
		AuthToken:              token,
	}, keyReq)
	if err != nil {
		return "", nil, fmt.Errorf("unable to deploy function: %w", err)
	}

	return id, checksum, nil
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

func zipSize(path string) (uint64, error) {
	var size uint64
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	for _, f := range r.File {
		size += f.UncompressedSize64
	}

	return size, nil
}

func getUsername() (string, error) {
	t, err := getAuthToken()
	if err != nil {
		return "", err
	}

	token, err := jwt.Parse([]byte(t), jwt.WithVerify(false))
	if err != nil {
		return "", err
	}

	return token.PrivateClaims()["https://capeprivacy.com/username"].(string), nil
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

var deployTmpl = `Function ID       ➜  {{ .ID }}
Function Checksum ➜  {{ .Checksum }}
Function Name     ➜  {{ .FunctionName }} 
`
