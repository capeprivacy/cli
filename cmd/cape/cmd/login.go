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

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

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
	deviceCodeResponse, err := newDeviceCode()
	if err != nil {
		return err
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
		return err
	}

	err = persistTokenResponse(tokenResponse)
	if err != nil {
		return err
	}

	fmt.Println("Congratulations, you're all set!")
	return nil
}

func newDeviceCode() (*DeviceCodeResponse, error) {
	deviceCodeURL := fmt.Sprintf("%s/oauth/device/code", C.AuthHost)
	payloadStr := fmt.Sprintf("client_id=%s&scope=openid%%20profile%%20email%%20offline_access&audience=%s", C.ClientID, C.Audience)
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
	tokenURL := fmt.Sprintf("%s/oauth/token", C.AuthHost)
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

func persistTokenResponse(response *TokenResponse) error {
	authJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}

	err = os.MkdirAll(C.LocalConfigDir, os.ModePerm)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(C.LocalConfigDir, C.LocalAuthFileName), authJSON, 0644)
	if err != nil {
		return err
	}

	return nil
}

func getTokenResponse() (*TokenResponse, error) {
	authFile, err := os.Open(filepath.Join(C.LocalConfigDir, C.LocalAuthFileName))
	if err != nil {
		return nil, err
	}
	defer authFile.Close()

	byteValue, err := ioutil.ReadAll(authFile)
	if err != nil {
		return nil, err
	}

	var response TokenResponse
	err = json.Unmarshal(byteValue, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func refreshTokenResponse(refreshToken string) error {
	deviceCodeURL := fmt.Sprintf("%s/oauth/token", C.AuthHost)
	payloadStr := fmt.Sprintf("grant_type=refresh_token&client_id=%s&refresh_token=%s", C.ClientID, refreshToken)
	req, err := http.NewRequest("POST", deviceCodeURL, strings.NewReader(payloadStr))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New("unable to refresh authentication details")
	}

	response := TokenResponse{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}

	response.RefreshToken = refreshToken
	err = persistTokenResponse(&response)
	if err != nil {
		return err
	}

	return nil
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
