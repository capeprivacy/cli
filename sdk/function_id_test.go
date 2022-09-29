package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/capeprivacy/cli/entities"
)

func testServer(t *testing.T, statusCode int) *httptest.Server {
	t.Helper()
	// a server that returns deployment info
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		deployment := entities.DeploymentName{
			ID:        "abc123",
			Name:      "isprime",
			CreatedAt: time.Now(),
		}
		if err := json.NewEncoder(w).Encode(deployment); err != nil {
			t.Fatal(err)
			return
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestGetFunctionID(t *testing.T) {
	s := testServer(t, http.StatusOK) // get a "supervisor"
	id, err := GetFunctionID(FunctionIDRequest{URL: s.URL, UserName: "github123", FunctionName: "isprime"})
	if err != nil {
		t.Error(err)
	}

	if got, want := id, "abc123"; got != want {
		t.Errorf("didn't get expected function id got %s, wanted %s", got, want)
	}
}

func TestGetFunctionID4xx(t *testing.T) {
	expectedCode := http.StatusBadRequest
	s := testServer(t, expectedCode)
	_, err := GetFunctionID(FunctionIDRequest{URL: s.URL, UserName: "github123", FunctionName: "no_such_func"})
	if got, want := err.Error(), fmt.Sprintf("HTTP Error: %d ", expectedCode); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestGetFunctionID5xx(t *testing.T) {
	expectedCode := http.StatusInternalServerError
	s := testServer(t, expectedCode)
	_, err := GetFunctionID(FunctionIDRequest{URL: s.URL, UserName: "no such user", FunctionName: "anyuser/func"})
	if got, want := err.Error(), fmt.Sprintf("HTTP Error: %d ", expectedCode); got != want {
		t.Errorf("didn't get expected error \ngot\n\t%s\nwant\n\t%s", got, want)
	}
}

func TestFunctionValidation(t *testing.T) {
	for _, tt := range []struct {
		name        string
		functionReq FunctionIDRequest
		want        string
	}{
		{
			"empty username name",
			FunctionIDRequest{
				"",
				"awesomefunc",
				"https:whatev.com",
				"logged in",
			},

			"please provide a username",
		},
		{
			"empty function name",
			FunctionIDRequest{
				"bob",
				"",
				"https:whatev.com",
				"logged in",
			},

			"please provide a function name",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetFunctionID(tt.functionReq)

			if got, want := err.Error(), tt.want; got != want {
				t.Errorf("didn't get expected output\ngot\n\t%s\nwanted\n\t%s", got, want)
			}
		})
	}
}
