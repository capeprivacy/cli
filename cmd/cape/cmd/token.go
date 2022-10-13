package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/render"
)

var privateKeyFile = "token.pem"
var publicKeyFile = "token.pub.pem"

var tokenCmd = &cobra.Command{
	Use:   "token <function_id>",
	Short: "Create a token to execute a cape function",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := token(cmd, args)
		if _, ok := err.(UserError); ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(tokenCmd)

	tokenCmd.PersistentFlags().IntP("expiry", "e", 3600, "optional time to live (in seconds)")
	tokenCmd.PersistentFlags().BoolP("owner", "", false, "optional owner token (debug logs)")
	tokenCmd.PersistentFlags().StringP("function-checksum", "", "", "optional function checksum")

	registerTemplate(tokenCmd.Name(), tokenTmpl)
}

func token(cmd *cobra.Command, args []string) error {
	url := C.EnclaveHost
	insecure := C.Insecure
	if len(args) < 1 {
		return fmt.Errorf("you must pass a function ID")
	}

	functionID := args[0]
	expiry, err := cmd.Flags().GetInt("expiry")
	if err != nil {
		return err
	}

	owner, err := cmd.Flags().GetBool("owner")
	if err != nil {
		return err
	}

	// This gets the token from login.
	accessTokenParsed, err := getAccessTokenVerifyAndParse()
	if err != nil {
		return err
	}

	functionChecksum, err := cmd.Flags().GetString("function-checksum")
	if err != nil {
		return err
	}

	// Use the AccessToken sub (user id) as the issuer for the function token.
	// The issuer is used to determine which KMS key to use inside the enclave.
	issuer := accessTokenParsed.Subject()
	if issuer == "" {
		return fmt.Errorf("could not detect your user id, perhaps retry logging in")
	}

	// Get the un-parsed access token.
	// (TODO) Optimize token retrieval so we only get auth token once.
	t, err := authToken()
	if err != nil {
		return err
	}
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: t}
	// Check that the signed in user has ownership access to the function before creating
	// the token for it.

	err = doGet(functionID, url, insecure, auth)
	if err != nil {
		return UserError{Msg: "failed to fetch function information", Err: err}
	}

	tokenString, err := Token(issuer, functionID, expiry, owner)
	if err != nil {
		log.Errorf("failed to create token for: %s, make sure you are the owner of the function.", functionID)
		return err
	}

	log.Infof("This token will expire in %s\n", time.Second*time.Duration(expiry))

	output := struct {
		ID       string `json:"function_id"`
		Token    string `json:"function_token"`
		Checksum string `json:"function_checksum"`
	}{
		ID:       functionID,
		Token:    tokenString,
		Checksum: functionChecksum,
	}

	return render.Ctx(cmd.Context()).Render(cmd.OutOrStdout(), output)
}

func Token(issuer string, functionID string, expires int, owner bool) (string, error) {
	privateKey, err := getOrGeneratePrivateKey()
	if err != nil {
		return "", err
	}

	var scope = []string{"function:invoke"}
	if owner {
		scope = append(scope, "function:output")
	}

	token, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(functionID).
		Claim("scope", strings.Join(scope, " ")).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Second * time.Duration(expires))).
		Build()
	if err != nil {
		return "", err
	}

	tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		return "", err
	}

	return string(tokenString), nil
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

func doGet(functionID string, url string, insecure bool, auth entities.FunctionAuth) error {
	endpoint := fmt.Sprintf("%s/v1/functions/%s", url, functionID)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return err
	}

	var bearer = "Bearer " + auth.Token
	req.Header.Add("Authorization", bearer)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return UserError{Msg: "failed to verify function ownership", Err: fmt.Errorf("cannot complete http request: %s", err)}
	}

	switch res.StatusCode {
	case http.StatusNotFound:
		return UserError{Msg: "function not found"}
	case http.StatusUnauthorized:
		return UserError{Msg: "unauthorized to create a function token for function"}
	case http.StatusOK:

	default:
		return UserError{Msg: fmt.Sprintf("expected 200, got server response code %d", res.StatusCode)}
	}

	var deployment entities.DeploymentName

	err = json.NewDecoder(res.Body).Decode(&deployment)
	if err != nil {
		return UserError{Msg: "malformed body in response"}
	}

	return nil
}

var tokenTmpl = "{{ .Token }}\n"
