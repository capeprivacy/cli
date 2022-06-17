package capetest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/capeprivacy/cli/attest"
	"github.com/gorilla/websocket"
)

func wsURL(origURL string) string {
	u, _ := url.Parse(origURL)
	u.Scheme = "ws"

	return u.String()
}

func TestCapeTest(t *testing.T) {
	runAttestation = func(attestation []byte) (*attest.AttestationDoc, error) { return &attest.AttestationDoc{}, nil }
	localEncrypt = func(doc attest.AttestationDoc, plaintext []byte) ([]byte, error) { return plaintext, nil }

	var gotFn []byte
	var gotInput []byte
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}

		var startReq StartRequest
		if err := c.ReadJSON(&startReq); err != nil {
			t.Fatal(err)
		}
		if err := c.WriteJSON(Message{}); err != nil {
			t.Fatal(err)
		} // write attestation doc back
		_, fn, err := c.ReadMessage()
		if err != nil {
			t.Fatal(err)
		} // read the function
		_, input, err := c.ReadMessage()
		if err != nil {
			t.Fatal(err)
		} // read the input

		gotFn, gotInput = fn, input
		if err := c.WriteJSON(RunResults{Message: []byte("results")}); err != nil {
			t.Fatal(err)
		}
	}))
	defer s.Close()

	test := TestRequest{
		Function: []byte("myfn"),
		Input:    []byte("myinput"),
	}

	res, err := CapeTest(test, wsURL(s.URL), true)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(res.Message), "results"; got != want {
		t.Fatalf("didn't get expected results, got %s, wanted %s", got, want)
	}

	if got, want := gotFn, test.Function; !reflect.DeepEqual(got, want) {
		t.Fatalf("didn't get expected function on the server\ngot\n\t%v\nwanted\n\t%v", got, want)
	}

	if got, want := gotInput, test.Input; !reflect.DeepEqual(got, want) {
		t.Fatalf("didn't get expected input on the server\ngot\n\t%v\nwanted\n\t%v", got, want)
	}
}
