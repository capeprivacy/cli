package oauth2device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestAuthorizationError(t *testing.T) {
	tests := []struct {
		name string
		in   AuthorizationError
		out  string
	}{
		{
			name: "only error provided",
			in:   AuthorizationError{Err: "foo"},
			out:  "foo",
		},
		{
			name: "error and description provided",
			in: AuthorizationError{
				Err:         "foo",
				Description: "bar",
			},
			out: "foo: bar",
		},
		{
			name: "all fields provided",
			in: AuthorizationError{
				Err:         "foo",
				Description: "bar",
				URI:         "baz",
			},
			out: "foo: bar (see baz)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := test.in.Error(), test.out; got != want {
				t.Errorf("incorrect string; got %q want %q", got, want)
			}
		})
	}
}

func TestContextClient(t *testing.T) {
	tests := []struct {
		name   string
		ctx    context.Context
		client *http.Client
	}{
		{
			name:   "nil context returns default client",
			ctx:    nil,
			client: http.DefaultClient,
		},
		{
			name:   "context with no client returns default client",
			ctx:    context.Background(),
			client: http.DefaultClient,
		},
		{
			name:   "context with client returns client",
			ctx:    context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: 20 * time.Minute}),
			client: &http.Client{Timeout: 20 * time.Minute},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := contextClient(test.ctx), test.client; !reflect.DeepEqual(got, want) {
				t.Errorf("incorrect client returned; got %#v want %#v", got, want)
			}
		})
	}
}

func TestDeviceCode(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		h    http.Handler
		dc   *DeviceCode
		err  error
	}{
		{
			name: "error fetching device code",
			ctx:  context.WithValue(context.Background(), oauth2.HTTPClient, errorClient),
			h:    http.NotFoundHandler(),
			dc:   nil,
			err:  ErrFetchDeviceCode,
		},
		{
			name: "http error fetching device code",
			ctx:  context.Background(),
			h:    http.NotFoundHandler(),
			dc:   nil,
			err:  ErrInvalidDeviceCode,
		},
		{
			name: "invalid device code returned",
			ctx:  context.Background(),
			h:    staticHandler(`{"device_code":42,"user_code":"bar"}`),
			dc:   nil,
			err:  ErrInvalidDeviceCode,
		},
		{
			name: "valid device code",
			ctx:  context.Background(),
			h:    staticHandler(`{"device_code":"foo","user_code":"bar"}`),
			dc: &DeviceCode{
				DeviceCode: "foo",
				UserCode:   "bar",
			},
			err: nil,
		},
		{
			name: "authorization error",
			ctx:  context.Background(),
			h:    staticHandler(`{"error":"foo"}`),
			dc:   nil,
			err:  AuthorizationError{Err: "foo"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(test.h)
			defer ts.Close()

			c := &Config{
				Config:         &oauth2.Config{},
				DeviceEndpoint: Endpoint{CodeURL: ts.URL},
			}

			dc, err := c.DeviceCode(test.ctx)

			if got, want := dc, test.dc; !reflect.DeepEqual(got, want) {
				t.Errorf("incorrect device code; got %#v want %#v", got, want)
			}

			if got, want := err, test.err; !reflect.DeepEqual(got, want) {
				t.Errorf("incorrect error; got %#v want %#v", got, want)
			}
		})
	}
}

func TestWaitHttpError(t *testing.T) {
	c := Config{
		Config: &oauth2.Config{
			Endpoint: oauth2.Endpoint{TokenURL: "this://is\nwrong"},
		},
	}
	_, err := c.Wait(context.Background(), new(DeviceCode))
	urlErr := &url.Error{Op: "parse", URL: "this://is\nwrong", Err: errors.New("net/url: invalid control character in URL")}
	if got, want := err, urlErr; !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect error;\n\t got %q\n\twant %q", got.Error(), want.Error())
	}
}

func TestWait(t *testing.T) {
	tests := []struct {
		name  string
		resps []string
		tok   *oauth2.Token
		err   error
	}{
		{
			name:  "invalid json response",
			resps: []string{`this{\nisn't good`},
			tok:   nil,
			err:   ErrFetchToken,
		},
		{
			name:  "valid token",
			resps: []string{`{"access_token":"foo","id_token":"bar"}`},
			tok: (&oauth2.Token{AccessToken: "foo"}).WithExtra(
				map[string]interface{}{"id_token": "bar"},
			),
			err: nil,
		},
		{
			name: "authorization pending",
			resps: []string{
				`{"error":"authorization_pending"}`,
				`{"access_token":"foo","id_token":"bar"}`,
			},
			tok: (&oauth2.Token{AccessToken: "foo"}).WithExtra(
				map[string]interface{}{"id_token": "bar"},
			),
			err: nil,
		},
		{
			name: "slow down",
			resps: []string{
				`{"error":"slow_down"}`,
				`{"access_token":"foo","id_token":"bar"}`,
			},
			tok: (&oauth2.Token{AccessToken: "foo"}).WithExtra(
				map[string]interface{}{"id_token": "bar"},
			),
			err: nil,
		},
		{
			name:  "access denied",
			resps: []string{`{"error":"access_denied"}`},
			tok:   nil,
			err:   ErrAccessDenied,
		},
		{
			name:  "other error",
			resps: []string{`{"error":"what in the!?"}`},
			tok:   nil,
			err:   errors.New("authorization failed: what in the!?"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var count int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, test.resps[count])
				count++
			}))
			defer srv.Close()

			c := Config{
				Config: &oauth2.Config{
					Endpoint: oauth2.Endpoint{TokenURL: srv.URL},
				},
			}

			tok, err := c.Wait(context.Background(), new(DeviceCode))
			if got, want := err, test.err; !reflect.DeepEqual(got, want) {
				t.Errorf("incorrect error;\n\t got %q\n\twant %q", got.Error(), want.Error())
				t.Logf("err: %#v", got)
			}

			if got, want := tok, test.tok; !reflect.DeepEqual(got, want) {
				t.Errorf("incorrect token;\n\t got %#v\n\twant %#v", got, want)
			}
		})
	}
}

type errorRoundTripper struct{}

func (e errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("nope")
}

var errorClient = &http.Client{Transport: errorRoundTripper{}}

func staticHandler(s string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s)
	})
}

/*
func (c *Config) DeviceCode(ctx context.Context) (*DeviceCode, error) {
func (c *Config) Wait(ctx context.Context, code *DeviceCode) (*oauth2.Token, error) {
*/
