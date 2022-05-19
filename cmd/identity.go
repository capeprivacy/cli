package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"
)

var apiURL = "http://localhost:8080"

type UserResponse struct {
	ID string `json:"id"`
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "query cape application for user identity",
	RunE:  identity,
}

func init() {
	rootCmd.AddCommand(identityCmd)
}

func identity(cmd *cobra.Command, args []string) error {
	accessToken, err := getAccessToken()
	if err != nil {
		return err
	}

	identity, err := getUserIdentity(*accessToken)
	if err != nil {
		return err
	}

	fmt.Printf("cape identity: %s\n", identity)
	return nil
}

func getAccessToken() (*string, error) {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		return nil, err
	}

	_, err = getUserIdentity(tokenResponse.AccessToken)
	if err == nil {
		return &tokenResponse.AccessToken, nil
	}

	err = refreshTokenResponse(tokenResponse.RefreshToken)
	if err != nil {
		return nil, err
	}

	tokenResponse, err = getTokenResponse()
	if err != nil {
		return nil, err
	}

	return &tokenResponse.AccessToken, nil
}

func getUserIdentity(accessToken string) (*UserResponse, error) {
	identityURL := fmt.Sprintf("%s/v1/user/identity", apiURL)
	req, err := http.NewRequest("GET", identityURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", accessToken))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, errors.New("invalid response code received")
	}

	return &UserResponse{ID: "TBD"}, nil
}
