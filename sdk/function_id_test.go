package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/capeprivacy/cli/entities"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	// a server that returns deployment info
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deployment := entities.Deployment{
			ID:                  "abc123",
			UserID:              "github123",
			Name:                "isprime",
			Location:            "mars",
			AttestationDocument: nil,
			CreatedAt:           time.Time{},
		}

		if err := json.NewEncoder(w).Encode(deployment); err != nil {
			t.Fatal(err)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(s.Close)

	return s
}

func TestFunctionID(t *testing.T) {
	s := testServer(t) // get a "supervisor"
	id, err := GetFunctionID(FunctionIDRequest{URL: s.URL, FunctionName: "github123/isprime"})
	if err != nil {
		t.Error(err)
	}

	if got, want := id, "abc123"; got != want {
		t.Errorf("didn't get expected function id got %s, wanted %s", got, want)
	}
}
