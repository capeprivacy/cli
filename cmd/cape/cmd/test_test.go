package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/capeprivacy/cli/capetest"
	czip "github.com/capeprivacy/cli/zip"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

const (
	help = `Test your function with Cape
Test will also read input data from stdin, example: "echo '1234' | cape run id".
Results are output to stdout so you can easily pipe them elsewhere

Usage:
  cape test directory [input] [flags]

Flags:
  -h, --help   help for test

`

	usage = `Usage:
  cape test directory [input] [flags]

Flags:
  -h, --help   help for test

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
	cmd.SetArgs([]string{"test", "testdata/my_fn", "hello world", "--url", s.URL})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("received unexpected error: %v, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
	}

	if got, want := stdout.String(), "hi!"; !reflect.DeepEqual(got, want) {
		t.Fatalf("didn't get expected results\ngot\n\t%s\nwanted\n\t%s", got, want)
	}
}

func TestHelp(t *testing.T) {
	stdErr := new(bytes.Buffer)
	stdOut := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetOut(stdOut)
	cmd.SetErr(stdErr)
	cmd.SetArgs([]string{"test", "-h"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := stdOut.String(), help; !strings.HasPrefix(got, want) {
		t.Fatalf("didn't get expected output, got %s, wanted %s", got, want)
	}
}
