package sdk

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/capeprivacy/cli/entities"

	"github.com/capeprivacy/cli/attest"
)

type testProtocol struct {
	start   func(req entities.StartRequest) error
	attest  func() ([]byte, error)
	results func() (*entities.RunResults, error)
	binary  func(b []byte) error
}

func (t testProtocol) WriteFunctionPublicKey(key string) error {
	return nil
}

func (t testProtocol) ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error) {
	return nil, nil
}

func (t testProtocol) WriteStart(request entities.StartRequest) error {
	return t.start(request)
}
func (t testProtocol) ReadAttestationDoc() ([]byte, error) { return t.attest() }
func (t testProtocol) ReadRunResults() (*entities.RunResults, error) {
	return t.results()
}
func (t testProtocol) WriteBinary(bytes []byte) error { return t.binary(bytes) }

func wsURL(origURL string) string {
	u, _ := url.Parse(origURL)
	u.Scheme = "ws"

	return u.String()
}

func TestCapeTest(t *testing.T) {
	runAttestation = func(attestation []byte, rootCert *x509.Certificate) (*attest.AttestationDoc, *attest.AttestationUserData, error) {
		return &attest.AttestationDoc{}, nil, nil
	}
	localEncrypt = func(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) { return plaintext, nil }

	getProtocolFn = func(ws *websocket.Conn) protocol {
		return testProtocol{
			start:  func(req entities.StartRequest) error { return nil },
			attest: func() ([]byte, error) { return []byte{}, nil },
			results: func() (*entities.RunResults, error) {
				return &entities.RunResults{Message: []byte("good job")}, nil
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

	res, err := Test(test, wsURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(res.Message), "good job"; got != want {
		t.Fatalf("didn't get expected results, got %s, wanted %s", got, want)
	}
}
