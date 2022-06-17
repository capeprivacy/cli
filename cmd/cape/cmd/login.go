package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/avast/retry-go"

	"github.com/capeprivacy/cli/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var C config.Config

type DeviceCodeResponse struct {
	VerificationURIComplete string `json:"verification_uri_complete"`
	UserCode                string `json:"user_code"`
	DeviceCode              string `json:"device_code"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to cape application",
	RunE:  login,
}

func init() {
	rootCmd.AddCommand(loginCmd)
}

func login(cmd *cobra.Command, args []string) error {
	err := Login(C.Hostname, C.ClientID, C.Audience, C.LocalAuthDir, C.LocalAuthFileName)
	if err != nil {
		return err
	}

	fmt.Println("Congratulations, you're all set!")
	return nil
}

func Login(hostname string, clientID string, audience string, dir string, filename string) error {
	tr, err := generateTokenResponse(hostname, clientID, audience)
	if err != nil {
		log.WithField("err", err).Error("unable to generate token response")
		return err
	}

	err = generateTokenFile(tr, dir, filename)
	if err != nil {
		log.WithField("err", err).Error("unable to generate token file")
		return err
	}

	return nil
}

func generateTokenFile(tr *TokenResponse, dir string, filename string) error {
	authJSON, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return err
	}

	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(dir, filename), authJSON, 0644)
	if err != nil {
		return err
	}

	return nil
}

func generateTokenResponse(hostname string, clientID string, audience string) (*TokenResponse, error) {
	deviceCodeResponse, err := newDeviceCode(hostname, clientID, audience)
	if err != nil {
		return nil, err
	}

	var tokenResponse *TokenResponse
	err = retry.Do(
		func() error {
			response, err := getToken(deviceCodeResponse.DeviceCode)
			tokenResponse = response
			return err
		},
		retry.Attempts(uint(deviceCodeResponse.ExpiresIn/deviceCodeResponse.Interval)),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(time.Duration(deviceCodeResponse.Interval)*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}

func newDeviceCode(hostname string, clientID string, audience string) (*DeviceCodeResponse, error) {
	deviceCodeURL := fmt.Sprintf("%s/oauth/device/code", hostname)
	payloadStr := fmt.Sprintf("client_id=%s&scope=openid%%20profile%%20email&audience=%s", clientID, audience)
	req, err := http.NewRequest("POST", deviceCodeURL, strings.NewReader(payloadStr))
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		log.Errorf("unable to login to cape, error: %s", res.Status)
	}

	response := DeviceCodeResponse{}
	err = json.Unmarshal(body, &response)

	if err != nil {
		return nil, err
	}
	if len(response.VerificationURIComplete) == 0 {
		return nil, errors.New("unknown response detected")
	}

	fmt.Printf("Your CLI confirmation code is: %s\n", response.UserCode)
	fmt.Printf("Visit this URL to complete the login process: %s\n", response.VerificationURIComplete)
	// Since we're printing the URL, we can safely ignore any error attempting to open the browser
	_ = openbrowser(response.VerificationURIComplete)

	return &response, nil
}

func getToken(deviceCode string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/oauth/token", C.Hostname)
	payload := strings.NewReader(fmt.Sprintf("grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s&client_id=%s", deviceCode, C.ClientID))
	req, _ := http.NewRequest("POST", tokenURL, payload)

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, errors.New("authorization pending")
	}

	response := TokenResponse{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Based on GIST: https://gist.github.com/hyg/9c4afcd91fe24316cbf0
func openbrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	}
	return fmt.Errorf("unsupported platform")
}
