package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testLinkServer(t *testing.T, statusCode int, errMsg *errorMsg) *httptest.Server {
	t.Helper()
	// a server that returns deployment info
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		if errMsg != nil {
			if err := json.NewEncoder(w).Encode(errMsg); err != nil {
				t.Fatal(err)
				return
			}
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestLink(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		errMsg  *errorMsg
		wantErr bool
	}{
		{
			"success",
			http.StatusCreated,
			nil,
			false,
		},
		{
			"bad gateway",
			http.StatusBadGateway,
			nil,
			true,
		},
		{
			"another error",
			http.StatusInternalServerError,
			&errorMsg{Message: "bad"},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := testLinkServer(t, test.status, test.errMsg)

			if err := LinkAWSAccount(s.URL, "token", "customer_id"); (err != nil) != test.wantErr {
				t.Errorf("LinkAWSAccount() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
