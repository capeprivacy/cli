package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/capeprivacy/cli/entities"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
)

// `cape token` uses the token subject from the currently logged in cape user.
// this helper creates a dummy auth file for that purpose.
func beforeOnce() (string, error) {
	// We cannot easily validate the JWKS in test as the test access token is self generated.
	getAccessTokenVerifyAndParse = func() (jwt.Token, error) {
		tokenResponse, err := getTokenResponse()
		if err != nil {
			return nil, err
		}
		return jwt.Parse([]byte(tokenResponse.AccessToken), jwt.WithVerify(false))
	}

	localConfigDir, err := os.MkdirTemp("", "config")
	if err != nil {
		return "", err
	}

	viper.Set("LOCAL_CONFIG_DIR", localConfigDir)

	accessToken, err := jwt.NewBuilder().
		Subject("github|test-user").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		return "", err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	accessTokenString, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return "", err
	}

	tokenResponse, err := json.MarshalIndent(&TokenResponse{
		AccessToken: string(accessTokenString),
	}, "", "  ")
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(localConfigDir, os.ModePerm)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(localConfigDir+"/auth", tokenResponse, 0644)
	if err != nil {
		return "", err
	}

	return localConfigDir, nil
}

func TestToken(t *testing.T) {
	previousLocalConfigDir := viper.Get("LOCAL_CONFIG_DIR")
	localConfigDir, err := beforeOnce()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(localConfigDir)
	defer viper.Set("LOCAL_CONFIG_DIR", previousLocalConfigDir)

	cmd, stdout, _ := getCmd()

	functionID := "5gWto31CNOTI"
	cmd.SetArgs([]string{"token", functionID})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	tokenOutput, err := jwt.Parse(stdout.Bytes(), jwt.WithVerify(false))
	if err != nil {
		t.Fatal(err)
	}

	if tokenOutput.Issuer() != "github|test-user" {
		t.Fatal("incorrect token issuer")
	}

	if tokenOutput.Subject() != functionID {
		t.Fatal("incorrect token subject")
	}

	if _, err := os.Open(filepath.Join(C.LocalConfigDir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Open(filepath.Join(C.LocalConfigDir, privateKeyFile)); err != nil {
		t.Fatal(err)
	}
}

type testDeployment struct {
	ID                  string    `json:"id"`
	UserID              string    `json:"user_id"`
	Name                string    `json:"name"`
	Location            string    `json:"location"`
	AttestationDocument []byte    `json:"attestation_document,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

func TestDoGet(t *testing.T) {
	myID := "megatron"
	myName := "octopusprime"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		response := testDeployment{
			ID:   myID,
			Name: myName,
		}

		enc := json.NewEncoder(w)

		err := enc.Encode(response)
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()
	myToken := "oneringtorulethemall"
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: myToken}
	err := doGet(myID, srv.URL, true, auth)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoGetFailed(t *testing.T) {
	myID := "megatron"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	myToken := "oneringtorulethemall"
	auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: myToken}
	err := doGet(myID, srv.URL, true, auth)
	if err == nil {
		t.Fatal(err)
	}
}
