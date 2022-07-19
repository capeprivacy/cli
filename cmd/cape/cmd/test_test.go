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

	"github.com/capeprivacy/cli/capetest"
	czip "github.com/capeprivacy/cli/zip"
)

const (
	help = `Test your function with Cape
Test will also read input data from stdin, example: "echo '1234' | cape test dir".
Results are output to stdout so you can easily pipe them elsewhere

Usage:
  cape test directory [input] [flags]

Flags:
  -f, --file string   input data file
  -h, --help          help for test

`

	usage = `Usage:
  cape test directory [input] [flags]

Flags:
  -f, --file string   input data file
  -h, --help          help for test

`
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
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), usage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestThreeArgs(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "fjkd", "fjkdsl"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), usage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestBadFunction(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/notafunction", "fjkd"})
	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), "Error: zipping directory failed: lstat testdata/notafunction: no such file or directory\n"; got != want {
		t.Errorf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), usage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestServerError(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world"})

	errMsg := "something went wrong"
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		return nil, errors.New(errMsg)
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
		authToken = getAuthToken
	}()

	if err := cmd.Execute(); err == nil {
		t.Fatal(errors.New("received no error when we should have"))
	}

	if got, want := stderr.String(), fmt.Sprintf("Error: %s\n", errMsg); got != want {
		t.Fatalf("didn't get expected stderr, got %s, wanted %s", got, want)
	}

	if got, want := stdout.String(), usage; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected response, got %s, wanted %s", got, want)
	}
}

func TestSuccess(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world"})

	results := "success!"
	var gotFn []byte
	var gotInput []byte
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		gotFn, gotInput = testReq.Function, testReq.Input
		return &capetest.RunResults{Message: []byte(results)}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
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

func TestSuccessStdin(t *testing.T) {
	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn"})

	results := "success!"
	var gotFn []byte
	var gotInput []byte
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		gotFn, gotInput = testReq.Function, testReq.Input
		return &capetest.RunResults{Message: []byte(results)}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
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
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		c, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
		if err != nil {
			return nil, err
		}
		defer c.Close()

		var m msg
		if err := c.ReadJSON(&m); err != nil {
			return nil, err
		}

		return &capetest.RunResults{Message: m.Message}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
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
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		endpointHit = endpoint
		return &capetest.RunResults{Message: []byte("good job")}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
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
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		endpointHit = endpoint
		return &capetest.RunResults{Message: []byte("good job")}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
		authToken = getAuthToken
	}()

	envEndpoint := "cape_env.com"
	os.Setenv("CAPE_HOSTNAME", envEndpoint)

	cmd, stdout, stderr := getCmd()
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Unexpected error: %v, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	if got, want := endpointHit, envEndpoint+"/v1/test"; got != want {
		t.Fatalf("didn't get expected endpoint, got %s, wanted %s", got, want)
	}
	cmd.Flags().Lookup("url").Changed = false
	os.Unsetenv("CAPE_HOSTNAME")
}

func TestFileConfigEndpoint(t *testing.T) {
	// ensure that env var overrides work for hostname
	endpointHit := ""
	test = func(testReq capetest.TestRequest, endpoint string, insecure bool) (*capetest.RunResults, error) {
		endpointHit = endpoint
		return &capetest.RunResults{Message: []byte("good job")}, nil
	}
	authToken = func() (string, error) {
		return "so logged in", nil
	}
	defer func() {
		test = capetest.CapeTest
		authToken = getAuthToken
	}()

	conf_dir := "/tmp/"
	os.Setenv("LOCAL_CONFIG_DIR", conf_dir)

	fileEndpoint := "https://foo_file.capeprivacy.com"
	conf := []byte("{\n  \"HOSTNAME\": \"" + fileEndpoint + "\"\n}\n")
	filename := "testconf.json"
	err := os.WriteFile(conf_dir+filename, conf, 0644)
	if err != nil {
		t.Fatalf("Unexpected error, could not write to temp conf file: %v", err)
	}

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

func TestHelp(t *testing.T) {
	cmd, stdout, _ := getCmd()
	cmd.SetArgs([]string{"test", "-h"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdout.String(), help; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected output, got %s, wanted %s", got, want)
	}
}
