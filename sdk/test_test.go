package sdk

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/capeprivacy/cli"

	"github.com/capeprivacy/attest/attest"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/mocks"
)

type testProtocol struct {
	start   func(req entities.StartRequest) error
	attest  func() ([]byte, error)
	results func() (*cli.RunResult, error)
	binary  func(b []byte) error
}

func (t testProtocol) WriteFunctionInfo(name string, public bool) error {
	return nil
}

func (t testProtocol) ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error) {
	return nil, nil
}

func (t testProtocol) WriteStart(request entities.StartRequest) error {
	return t.start(request)
}
func (t testProtocol) ReadAttestationDoc() ([]byte, error) { return t.attest() }
func (t testProtocol) ReadRunResults() (*cli.RunResult, error) {
	return t.results()
}
func (t testProtocol) WriteBinary(bytes []byte) error { return t.binary(bytes) }

func wsURL(origURL string) string {
	u, _ := url.Parse(origURL)
	u.Scheme = "ws"

	return u.String()
}

func TestCapeTest(t *testing.T) {
	verifier := mocks.MockVerifier{
		VerifyFn: func(attestation []byte, nonce []byte) (*attest.AttestationDoc, error) {
			return &attest.AttestationDoc{}, nil
		},
	}

	localEncrypt = func(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) { return plaintext, nil }

	getProtocolFn = func(ws *websocket.Conn) protocol {
		return testProtocol{
			start:  func(req entities.StartRequest) error { return nil },
			attest: func() ([]byte, error) { return []byte{}, nil },
			results: func() (*cli.RunResult, error) {
				return &cli.RunResult{Message: []byte("good job")}, nil
			},
			binary: func(b []byte) error { return nil },
		}
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		_, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer s.Close()

	test := TestRequest{
		Function: []byte("myfn"),
		Input:    []byte("myinput"),
		Insecure: true,
	}

	res, err := Test(test, verifier, wsURL(s.URL), []string{})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(res.Message), "good job"; got != want {
		t.Fatalf("didn't get expected results, got %s, wanted %s", got, want)
	}
}

func TestTransformURL(t *testing.T) {
	var tests = []struct {
		name        string
		url         string
		transformed string
	}{
		{
			name:        "transform http to ws",
			url:         "http://hellothere.capeprivacy.com",
			transformed: "ws://hellothere.capeprivacy.com",
		},
		{
			name:        "transform https to wss",
			url:         "https://goodbye.capeprivacy.com",
			transformed: "wss://goodbye.capeprivacy.com",
		},
		{
			name:        "do not transform wss",
			url:         "wss://seeyou.capeprivacy.com",
			transformed: "wss://seeyou.capeprivacy.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := transformURL(tt.url)
			if got != tt.transformed {
				t.Errorf("got unexpected transformed URL: got %v, want %v", got, tt.transformed)
			}
		})
	}
}
