package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/capeprivacy/cli/entities"
)

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
			testDeployment{
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
			testDeployment{
				ID:                  "abc123",
				UserID:              "bob",
				Name:                "coolfn",
				Location:            "",
				AttestationDocument: nil,
			},
			UserError{Msg: "unauthorized to create a function token for function", Err: errors.New("WCn2bmNtnRoz6hkdnGuRW3")},
		},
		{
			"function not found",
			"WCn2bmNtnRoz6hkdnGuRW3",
			"alice",
			http.StatusNotFound,
			testDeployment{
				ID:                  "abc123",
				UserID:              "bob",
				Name:                "coolfn",
				Location:            "",
				AttestationDocument: nil,
			},
			UserError{Msg: "function not found", Err: errors.New("WCn2bmNtnRoz6hkdnGuRW3")},
		},
		{
			"Any other errors",
			"WCn2bmNtnRoz6hkdnGuRW3",
			"alice",
			http.StatusConflict,
			testDeployment{
				ID:                  "abc123",
				UserID:              "bob",
				Name:                "coolfn",
				Location:            "",
				AttestationDocument: nil,
			},
			httpError(http.StatusConflict),
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
			auth := entities.FunctionAuth{Type: entities.AuthenticationTypeUserToken, Token: myToken}
			err := doGet(tt.id, srv.URL, true, auth)

			if got, want := err, tt.wantErr; !reflect.DeepEqual(got, want) {
				t.Fatalf("didn't get expected error\ngot\n\t%v\nwanted\n\t%v", got, want)
			}
		})
	}
}

func TestAcctToken(t *testing.T) {
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		authToken = getAuthToken
	}()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(createTokenResponse{Token: "yourjwtgoeshere"})
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)
	}))
	defer s.Close()

	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"token", "create", "--name", "my-token", "--function", "1234", "--url", s.URL})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), "yourjwtgoeshere\n"; got != want {
		t.Fatalf("didn't get expected output, got %s, wanted %s", got, want)
	}
}

func TestListTokens(t *testing.T) {
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		authToken = getAuthToken
	}()
	local, _ := time.LoadLocation("UTC")
	now, _ := time.Parse("Jan 02 2006 15:04", "Jan 02 2006 15:04")
	now = now.In(local)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal([]tokenRef{
			{ID: "aaa", Name: "abc", Description: "my first token", CreatedAt: now},
			{ID: "bbb", Name: "abc", Description: "my second token", CreatedAt: now},
			{ID: "ccc", Name: "abc", Description: "my third token", CreatedAt: now},
			{ID: "ddd", Name: "abc", Description: "my fourth token", CreatedAt: now},
		})

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer s.Close()

	cmd, _, _ := getCmd()
	cmd.SetArgs([]string{"token", "list", "--url", s.URL})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestTokenDelete(t *testing.T) {
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		authToken = getAuthToken
	}()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"token", "delete", "abc123", "--url", s.URL})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), "Deleted token abc123\n"; got != want {
		t.Fatalf("didn't get expected result, got %s, wanted %s", got, want)
	}
}
