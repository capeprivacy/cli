package oauth2device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// A DeviceAuthorizationResponse is returned by the server in response to
// device authorization request. See
// https://www.rfc-editor.org/rfc/rfc8628#section-3.2
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// An AuthorizationError is the response sent by authorization server. See
// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
type AuthorizationError struct {
	Err         string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri"`
}

// Error implements error
func (e AuthorizationError) Error() string {
	if e.Description == "" && e.URI == "" {
		return e.Err
	}

	if e.URI == "" {
		return fmt.Sprintf("%s: %s", e.Err, e.Description)
	}

	return fmt.Sprintf("%s: %s (see %s)", e.Err, e.Description, e.URI)
}

// Endpoint contains the URLs required to initiate the OAuth2.0 flow for a
// provider's device flow.
type Endpoint struct {
	CodeURL string
}

// A Config is an oauth2.Config with an endpoint for the device flow
type Config struct {
	*oauth2.Config
	DeviceEndpoint Endpoint
	Audience       string
}

var (
	ErrFetchDeviceCode   = errors.New("error fetching device code")
	ErrInvalidDeviceCode = errors.New("invalid device code")
	ErrFetchToken        = errors.New("error fetching token")
	ErrAccessDenied      = errors.New("access denied by user")
)

const (
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// contextClient returns the oauth2 HTTP client from the context, or the
// default client if one is not present.
func contextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}

// RequestDeviceCode will initiate the OAuth2 device authorization flow. It
// requests a device code and information on the code and URL to show to the
// user. Pass the returned DeviceCode to WaitForDeviceAuthorization.
func (c *Config) DeviceCode(ctx context.Context) (*DeviceCode, error) {
	scopes := strings.Join(c.Scopes, " ")
	resp, err := contextClient(ctx).PostForm(
		c.DeviceEndpoint.CodeURL,
		url.Values{
			"client_id": {c.ClientID},
			"scope":     {scopes},
			"audience":  {c.Audience},
		},
	)
	if err != nil {
		return nil, ErrFetchDeviceCode
	}

	var dc struct {
		*DeviceCode
		*AuthorizationError
	}
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return nil, ErrInvalidDeviceCode
	}

	if dc.AuthorizationError != nil {
		return nil, *dc.AuthorizationError
	}

	return dc.DeviceCode, nil
}

// Wait polls the token URL waiting for the user to
// authorize the app. Upon authorization, it returns the new token. If
// authorization fails then an error is returned. If that failure was due to a
// user explicitly denying access, the error is ErrAccessDenied.
func (c *Config) Wait(ctx context.Context, code *DeviceCode) (*oauth2.Token, error) {
	for {
		resp, err := contextClient(ctx).PostForm(c.Endpoint.TokenURL,
			url.Values{
				"client_secret": {c.ClientSecret},
				"client_id":     {c.ClientID},
				"device_code":   {code.DeviceCode},
				"grant_type":    {deviceGrantType}})
		if err != nil {
			return nil, err
		}

		var tok struct {
			*oauth2.Token
			IDToken string `json:"id_token,omitempty"`
			*AuthorizationError
		}
		if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
			return nil, ErrFetchToken
		}

		if tok.AuthorizationError == nil {
			return tok.Token.WithExtra(map[string]interface{}{
				"id_token": tok.IDToken,
			}), nil
		}

		switch tok.AuthorizationError.Err {
		case "authorization_pending":
			// do nothing; wait for user to authorize
		case "slow_down":
			code.Interval *= 2
		case "access_denied":
			return nil, ErrAccessDenied
		default:
			return nil, fmt.Errorf("authorization failed: %s", tok.Error())
		}

		time.Sleep(time.Duration(code.Interval) * time.Second)
	}
}
