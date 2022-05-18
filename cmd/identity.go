package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var apiURL = "https://newdemo.capeprivacy.com"

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "query cape application for user identity",
	RunE:  identity,
}

func init() {
	rootCmd.AddCommand(identityCmd)
}

func identity(cmd *cobra.Command, args []string) error {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		return err
	}

	err = getUserIdentity(tokenResponse.AccessToken)
	if err != nil {
		return err
	}

	return nil
}

func getTokenResponse() (*TokenResponse, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	authFile, err := os.Open(fmt.Sprintf("%s/%s/%s", home, localAuthDir, localAuthFileName))
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

func getUserIdentity(accessToken string) error {
	identityURL := fmt.Sprintf("%sv1/user/identity", apiURL)
	req, err := http.NewRequest("GET", identityURL, nil)
	if err != nil {
		return err
	}

	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", accessToken))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New("invalid response code received")
	}

	return nil
}

func setLoginCookie(req *http.Request) error {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		return err
	}

	t := tokenResponse.AccessToken
	if t == ""{
		return errors.New("empty access token")
	}

	req.AddCookie(&http.Cookie{Name: "login_token", Value: tokenResponse.AccessToken})
	return nil
}
