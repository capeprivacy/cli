package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	httpClient *http.Client
}

func New(httpClient *http.Client) *Client {
	return &Client{
		httpClient: httpClient,
	}
}

type HTTPClient interface {
	Get(path string) (*http.Response, error)
	Post(path string, payload interface{}) (*http.Response, error)
}

func (c *Client) Get (path string) (*http.Response, error) {
	req, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil{
		return nil, err
	}

	return resp, nil
}

func (c *Client) Post (path string, payload interface{}) (*http.Response, error) {
	req, err := c.newRequest(http.MethodGet, path, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil{
		return nil, err
	}

	return resp, nil
}

func (c *Client) newRequest (method, endpoint string, payload interface{}) (*http.Request, error) {
	var reqBody io.Reader
	if payload != nil {
		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequest(method, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	err = addBearerToken(req)
	if err != nil {
		return nil, fmt.Errorf("error setting bearer token in request")
	}
	return req, nil
}

// Returning http.response so Get and Post implementations can be flexible enough to evaluate the http.statuscode however they want to
func (c *Client) doRequest(r *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to make request [%s:%s]: %w", r.Method, r.URL.String(), err)
	}

	return resp, nil
}

func addBearerToken(req *http.Request) error {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		return err
	}

	t := tokenResponse.AccessToken
	if t == "" {
		return errors.New("empty access token")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t))
	return nil
}