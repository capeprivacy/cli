package sdk

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	for _, tt := range []struct {
		name    string
		server  http.HandlerFunc
		wantErr error
	}{
		{
			"encrypts data",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				f, err := os.ReadFile("./testdata/key.json")
				if err != nil {
					t.Error(err)
				}

				if _, err := w.Write(f); err != nil {
					t.Error(err)
				}
			},
			nil,
		},
		{
			"bad server response",
			func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusInternalServerError)
			},
			fmt.Errorf("something went wrong, status code: 500"),
		},
		{
			"bad server response unexpected data",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"jfkdfs": "fjkslfdk"}"`))
			},
			fmt.Errorf("something went wrong, status code: 500"),
		},
		{
			"bad server response with error",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "server is broken"}"`))
			},
			fmt.Errorf("server is broken"),
		},
		{
			"bad server response with message",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"message": "server is broken"}"`))
			},
			fmt.Errorf("server is broken"),
		},
		{
			"bad attestation document",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"attestation_document": "fjkdsfksdfk`)) // will EOF error (bad json)
			},
			fmt.Errorf("error parsing attestation document"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(tt.server)
			defer s.Close()

			result, err := Encrypt("hello", "bendecoste", WithURL(s.URL))

			if got, want := err, tt.wantErr; want != nil && !reflect.DeepEqual(got, want) {
				t.Fatalf("didn't get expected error\ngot\n\t%v\nwanted\n\t%v", got, want)
			}

			if tt.wantErr == nil && !strings.HasPrefix(result, "cape:") {
				t.Errorf("result not in expected format: %s", result)
			}
		})
	}
}
