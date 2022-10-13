package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"

	"github.com/capeprivacy/cli/entities"
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
	myID := "5gWto31CNOTI"
	myName := "test-user"
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

	previousLocalConfigDir := viper.Get("LOCAL_CONFIG_DIR")
	localConfigDir, err := beforeOnce()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(localConfigDir)
	defer viper.Set("LOCAL_CONFIG_DIR", previousLocalConfigDir)

	cmd, stdout, _ := getCmd()
	// Have to set the url explicitly, will break other tests if it relies on
	// URL.
	viper.Set("ENCLAVE_HOST", srv.URL)
	functionID := "5gWto31CNOTI"
	cmd.SetArgs([]string{"token", functionID})
	cmd.Flags().Set("url", srv.URL)
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
	for _, tt := range []struct {
		name         string
		id           string
		functionName string
		wantStatus   int
		response     any
		wantErr      error
	}{
		{
			"success",
			"WCn2bmNtnRoz6hkdnGuRW2",
			"bob",
			http.StatusOK,
			entities.Deployment{
				ID:                  "megatron",
				UserID:              "bob",
				Name:                "octopusprime",
				Location:            "",
				AttestationDocument: nil,
			},
			nil,
		},
		{
			"unauthorized",
			"WCn2bmNtnRoz6hkdnGuRW3",
			"alice",
			http.StatusUnauthorized,
			entities.Deployment{
				ID:                  "abc123",
				UserID:              "bob",
				Name:                "coolfn",
				Location:            "",
				AttestationDocument: nil,
			},
			errors.New("unauthorized to create a function token for function"),
		},
		{
			"function not found",
			"WCn2bmNtnRoz6hkdnGuRW3",
			"alice",
			http.StatusNotFound,
			entities.Deployment{
				ID:                  "abc123",
				UserID:              "bob",
				Name:                "coolfn",
				Location:            "",
				AttestationDocument: nil,
			},
			errors.New("function not found"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tt.wantStatus)
				enc := json.NewEncoder(w)

				err := enc.Encode(tt.response)
				if err != nil {
					t.Fatal(err)
				}
			}))
			defer srv.Close()
			myToken := "oneringtorulethemall"
			auth := entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: myToken}
			err := doGet(tt.id, srv.URL, true, auth)

			if got, want := err, tt.wantErr; !reflect.DeepEqual(got, want) {
				t.Fatalf("didn't get expected error\ngot\n\t%v\nwanted\n\t%v", got, want)
			}
		})
	}
}
