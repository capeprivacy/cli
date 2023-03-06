package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/sdk"
	czip "github.com/capeprivacy/cli/zip"
)

func getCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	stderr := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	return cmd, stdout, stderr
}

func wsURL(origURL string) string {
	u, _ := url.Parse(origURL)
	u.Scheme = "ws"

	return u.String()
}

func TestNoArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"test"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("output did not contain usage")
	}
}

func TestThreeArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "fjkd", "fjkdsl"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("output did not contain usage")
	}
}

func TestBadFunction(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/notafunction", "fjkd"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), "Error: unable to zip specified directory: zipping directory failed: lstat notafunction: no such file or directory\n"; got != want {
		t.Errorf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("output did not contain usage")
	}
}

func TestServerError(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world"})

	errMsg := "something went wrong"
	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		return nil, errors.New(errMsg)
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), fmt.Sprintf("Error: %s\n", errMsg); got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), ""; got != want {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestSuccess(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world"})

	results := "success!"
	var gotFn []byte
	var gotInput []byte
	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		gotFn, gotInput = testReq.Function, testReq.Input
		return &entities.RunResults{Message: []byte(results)}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stderr.String(), ""; got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), results; got != want {
		t.Fatalf("didn't get expected stdout, got %s, wanted %s", got, want)
	}

	want, err := czip.Create("./testdata/my_fn")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gotFn, want; !reflect.DeepEqual(got, want) {
		t.Fatalf("didn't get expected function bytes\ngot\n\t%v\nwanted\n\t%v", got, want)
	}

	if got, want := string(gotInput), "hello world"; got != want {
		t.Fatalf("didn't get expected input, got %s, wanted %s", got, want)
	}
}

func TestSuccessStdin(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "-f", "-"})

	results := "success!"
	var gotFn []byte
	var gotInput []byte
	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		gotFn, gotInput = testReq.Function, testReq.Input
		return &entities.RunResults{Message: []byte(results)}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	buf := bytes.NewBuffer([]byte("hello world"))
	cmd.SetIn(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stderr.String(), ""; got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), results; got != want {
		t.Fatalf("didn't get expected stdout, got %s, wanted %s", got, want)
	}

	want, err := czip.Create("testdata/my_fn")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gotFn, want; !reflect.DeepEqual(got, want) {
		t.Fatalf("didn't get expected function bytes\ngot\n\t%v\nwanted\n\t%v", got, want)
	}

	if got, want := string(gotInput), "hello world"; got != want {
		t.Fatalf("didn't get expected input, got %s, wanted %s", got, want)
	}
}

func TestWSConnection(t *testing.T) {
	type msg struct {
		Message []byte `json:"msg"`
	}
	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		c, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
		if err != nil {
			return nil, err
		}
		defer c.Close()

		var m msg
		if err := c.ReadJSON(&m); err != nil {
			return nil, err
		}

		return &entities.RunResults{Message: m.Message}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		if err := c.WriteJSON(msg{
			Message: []byte("hi!"),
		}); err != nil {
			t.Fatal(err)
		}
	}))

	defer s.Close()
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world", "--url", wsURL(s.URL)})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("received unexpected error: %v, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
	}

	if got, want := stdout.String(), "hi!"; !reflect.DeepEqual(got, want) {
		t.Fatalf("didn't get expected results\ngot\n\t%s\nwanted\n\t%s", got, want)
	}
	cmd.Flags().Lookup("url").Changed = false
}

func TestEndpoint(t *testing.T) {
	// ensure that `cape test` hits the `/v1/test` endpoint
	endpointHit := ""
	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		endpointHit = endpoint
		return &entities.RunResults{Message: []byte("good job")}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world", "--url", "cape.com"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Unexpected error: %v, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	if got, want := endpointHit, "cape.com/v1/test"; got != want {
		t.Fatalf("didn't get expected endpoint, got %s, wanted %s", got, want)
	}
	cmd.Flags().Lookup("url").Changed = false
}

func TestEnvVarConfigEndpoint(t *testing.T) {
	// ensure that env var overrides work for hostname
	endpointHit := ""
	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		endpointHit = endpoint
		return &entities.RunResults{Message: []byte("good job")}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
	}()

	envEndpoint := "cape_env.com"
	os.Setenv("CAPE_ENCLAVE_HOST", envEndpoint)

	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Unexpected error: %v, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	if got, want := endpointHit, envEndpoint+"/v1/test"; got != want {
		t.Fatalf("didn't get expected endpoint, got %s, wanted %s", got, want)
	}
	cmd.Flags().Lookup("url").Changed = false
	os.Unsetenv("CAPE_ENCLAVE_HOST")
}

func TestFileConfigEndpoint(t *testing.T) {
	// ensure that env var overrides work for hostname
	endpointHit := ""
	fileEndpoint := "https://foo_file.capeprivacy.com"
	oldEndpoint := os.Getenv("CAPE_ENCLAVE_HOST")

	test = func(testReq sdk.TestRequest, verifier sdk.Verifier, endpoint string, pcrSlice []string) (*entities.RunResults, error) {
		endpointHit = endpoint
		return &entities.RunResults{Message: []byte("good job")}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	readConfFile = func() error {
		_ = os.Setenv("CAPE_ENCLAVE_HOST", fileEndpoint)
		return nil
	}
	defer func() {
		test = sdk.Test
		authToken = getAuthToken
		readConfFile = viper.ReadInConfig
		_ = os.Setenv("CAPE_ENCLAVE_HOST", oldEndpoint)
	}()

	cmd, stdout, stderr := getCmd()

	// omit url from command
	cmd.SetArgs([]string{"test", "--config", "conf.json", "testdata/my_fn", "hello world"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Unexpected error: %v, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	if got, want := endpointHit, fileEndpoint+"/v1/test"; got != want {
		t.Fatalf("didn't get expected endpoint, got %s, wanted %s", got, want)
	}
}
