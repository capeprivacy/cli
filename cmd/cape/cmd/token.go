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

	"github.com/jedib0t/go-pretty/v6/table"
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
		// If it is not a user error, don't show usage help
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

type createTokenReq struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	FunctionID  string     `json:"function_id"`
	Expiry      *time.Time `json:"expiry,omitempty"`
}

type tokenRef struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`

	Expiry   *time.Time `json:"expiry,omitempty"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

type createTokenResponse struct {
	Token string `json:"token"`
}

var listTokensCmd = &cobra.Command{
	Use:   "list",
	Short: "List your account tokens",
	Long: `List the tokens from your account.

NOTE -- this will not list function tokens (ones made with cape token <function_id>).
This will be fixed in the future.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}

		url := C.EnclaveHost
		req, err := http.NewRequest(http.MethodGet, url+"/v1/tokens", nil)
		if err != nil {
			return err
		}

		authToken, err := authToken()
		if err != nil {
			return err
		}

		var bearer = "Bearer " + authToken
		req.Header.Add("Authorization", bearer)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			cmd.SilenceUsage = true
			if verbose {
				fmt.Println("received status code", resp.StatusCode)
			}

			return fmt.Errorf("something went wrong")
		}

		var toks []tokenRef
		if err := json.NewDecoder(resp.Body).Decode(&toks); err != nil {
			return err
		}

		if len(toks) == 0 {
			if _, err := cmd.OutOrStdout().Write([]byte("No tokens found. You can create tokens with cape token create\n")); err != nil {
				return err
			}

			return nil
		}

		t := table.NewWriter()
		t.SetOutputMirror(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "Name", "Description", "Created At", "Last Used", "Expires"})
		localTime, err := time.LoadLocation("Local")
		if err != nil {
			return err
		}

		for _, token := range toks {
			createdAt := token.CreatedAt.In(localTime).Format("Jan 02 2006 15:04")
			lastUsed := "Never"
			if lu := token.LastUsed; lu != nil {
				lastUsed = lu.In(localTime).Format("Jan 02 2006 15:04")
			}

			expiry := "Never"
			if exp := token.Expiry; exp != nil {
				expiry = exp.In(localTime).Format("Jan 02 2006 15:04")
			}

			t.AppendRow([]interface{}{token.ID, token.Name, token.Description, createdAt, lastUsed, expiry})
		}
		t.SetStyle(table.StyleLight)
		t.Render()

		return nil
	},
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a token for your account",
	Long: `Create a token for your account.

Use this command if you want a token that identifies you and scoped to a specific function. During creation
you pass a function id with --function flag and then this token can only be used to run that function.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}

		description, err := cmd.Flags().GetString("description")
		if err != nil {
			return err
		}

		functionID, err := cmd.Flags().GetString("function")
		if err != nil {
			return err
		}

		expiry, err := cmd.Flags().GetString("expiry")
		if err != nil {
			return err
		}

		if name == "" {
			return fmt.Errorf("token names must be alphanumeric")
		}

		url := C.EnclaveHost

		ctr := createTokenReq{
			Name:        name,
			Description: description,
			FunctionID:  functionID,
		}

		if expiry != "" {
			duration, err := time.ParseDuration(expiry)
			if err != nil {
				return err
			}

			exp := time.Now().UTC().Add(duration)
			ctr.Expiry = &exp
		}

		b, err := json.Marshal(ctr)

		if err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodPost, url+"/v1/token", bytes.NewReader(b))
		if err != nil {
			return err
		}

		authToken, err := authToken()
		if err != nil {
			return err
		}

		var bearer = "Bearer " + authToken
		req.Header.Add("Authorization", bearer)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusCreated {
			cmd.SilenceUsage = true
			if verbose {
				fmt.Println("received status code", resp.StatusCode)
				var errMsg ErrorMsg
				if err := json.NewDecoder(resp.Body).Decode(&errMsg); err != nil {
					fmt.Println("could not decode response body")
				} else {
					fmt.Println("received server error: ", errMsg.Error)
				}
			}

			return fmt.Errorf("something went wrong, your token was not created")
		}

		var tokenResponse createTokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			return err
		}

		if _, err := cmd.OutOrStdout().Write([]byte(tokenResponse.Token + "\n")); err != nil {
			return err
		}

		return nil
	},
}

var deleteTokenCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete tokens from your account",
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}

		tokenIDStr := args[0]
		url := C.EnclaveHost

		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/token/%s", url, tokenIDStr), nil)
		if err != nil {
			return err
		}

		authToken, err := authToken()
		if err != nil {
			return err
		}

		var bearer = "Bearer " + authToken
		req.Header.Add("Authorization", bearer)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			cmd.SilenceUsage = true
			if verbose {
				fmt.Println("received status code", resp.StatusCode)
				var errMsg ErrorMsg
				if err := json.NewDecoder(resp.Body).Decode(&errMsg); err != nil {
					fmt.Println("could not decode response body")
				} else {
					fmt.Println("received server error: ", errMsg.Error)
				}
			}

			return fmt.Errorf("something went wrong, your token was not deleted")
		}

		if _, err := cmd.OutOrStdout().Write([]byte(fmt.Sprintf("Deleted token %s\n", tokenIDStr))); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	tokenCmd.AddCommand(listTokensCmd)
	tokenCmd.AddCommand(createCmd)
	tokenCmd.AddCommand(deleteTokenCmd)

	rootCmd.AddCommand(tokenCmd)

	createCmd.PersistentFlags().StringP("name", "n", "", "the name for your token")
	createCmd.PersistentFlags().StringP("description", "d", "", "a description for your token")
	createCmd.PersistentFlags().StringP("expiry", "e", "", "a duration which your token will be valid for (e.g., 1h)")
	createCmd.PersistentFlags().StringP("function", "f", "", "the function which can be called with this token")

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
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken, Token: t}
	// Check that the signed in user has ownership access to the function before creating
	// the token for it.

	err = doGet(functionID, url, insecure, auth)
	if err != nil {
		return err
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
	case http.StatusOK:

	case http.StatusNotFound:
		return UserError{Msg: "function not found", Err: errors.New(functionID)}
	case http.StatusUnauthorized:
		return UserError{Msg: "unauthorized to create a function token for function", Err: errors.New(functionID)}

	default:
		return fmt.Errorf("expected 200, got server response code %d", res.StatusCode)
	}

	var deployment entities.Deployment

	err = json.NewDecoder(res.Body).Decode(&deployment)
	if err != nil {
		return errors.New("malformed body in response")
	}

	return nil
}

var tokenTmpl = "{{ .Token }}\n"
