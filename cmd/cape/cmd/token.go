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
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/entities"
)

var privateKeyFile = "token.pem"
var publicKeyFile = "token.pub.pem"

var tokenCmd = &cobra.Command{
	Use:   "token <subcommand>",
	Short: "Commands for working with tokens",
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

		authToken, err := getAuthTokenFlagOrOther(cmd)
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
	Long: `Cape Token Create

Create a Personal Access Token (PAT) that uniquely identifies you.
Currently, tokens can only be used to perform cape run.

By default, a token is able to run any function that its creator is allowed to run and they do not expire.
You can scope a token to an individual function with the --function flag.
You can set an expiry of the token with the --expiry flag.
`,
	Example: `  cape token create -n my-token -d 'for testing'                  Create a token that can run anything
  cape token create -n my-token -f Nm672nXZQnBe9vL4zedGJb         Create a token that can only run the function Nm672nXZQnBe9vL4zedGJb
  cape token create -n my-token -e 1h                             Create a token that can run anything that expires in 1 hour
  cape token create -n my-token -f Nm672nXZQnBe9vL4zedGJb -e 1h   Create a token that can run Nm672nXZQnBe9vL4zedGJb that expires in 1 hour`,

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

		authToken, err := getAuthTokenFlagOrOther(cmd)
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

		authToken, err := getAuthTokenFlagOrOther(cmd)
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
	tokenCmd.PersistentFlags().StringP("token", "t", "", "An optional token to use")

	registerTemplate(tokenCmd.Name(), tokenTmpl)
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

func getAuthTokenFlagOrOther(cmd *cobra.Command) (string, error) {
	token, err := cmd.Flags().GetString("token")
	if err != nil {
		return "", err
	}

	if token != "" {
		return token, nil
	}

	return authToken()
}
