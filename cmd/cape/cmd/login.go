package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"

	"golang.org/x/oauth2"

	"github.com/capeprivacy/cli/oauth2device"
	"github.com/capeprivacy/cli/sdk"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to Cape",
	Long: `Authenticate to Cape.

Authentication is a web-based browser flow. After completion,
an authentication token will be stored internally.
`,
	RunE: login,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.PersistentFlags().String("link-aws-account", "", "aws account to link with github account in Cape")
}

func login(cmd *cobra.Command, args []string) error {
	cfg := &oauth2.Config{
		ClientID: C.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", C.AuthHost),
			TokenURL: fmt.Sprintf("%s/oauth/token", C.AuthHost),
		},
		Scopes: []string{"openid", "profile", "email", "offline_access"},
	}

	dCfg := &oauth2device.Config{
		Config: cfg,
		DeviceEndpoint: oauth2device.Endpoint{
			CodeURL: fmt.Sprintf("%s/oauth/device/code", C.AuthHost),
		},
		Audience: C.Audience,
	}

	dc, err := dCfg.DeviceCode(context.TODO())
	if err != nil {
		return err
	}

	fmt.Printf("Your CLI confirmation code is: %s\n", dc.UserCode)
	fmt.Printf("Visit this URL to complete the login process: %s\n", dc.VerificationURIComplete)
	// Since we're printing the URL, we can safely ignore any error attempting to open the browser
	_ = openbrowser(dc.VerificationURIComplete)

	tok, err := dCfg.Wait(context.TODO(), dc)
	if err != nil {
		if errors.Is(err, oauth2device.ErrAccessDenied) {
			cmd.SilenceUsage = true
		}
		return err
	}

	err = persistTokenResponse(tok)
	if err != nil {
		return err
	}

	authToken, err := getAuthToken()
	if err != nil {
		return err
	}

	keyReq, err := GetKeyRequest([]string{}, authToken)
	if err != nil {
		return err
	}

	_, err = sdk.Key(keyReq)
	if err != nil {
		fmt.Println("Unable to fetch cape key, try running 'cape key' after login")
	}

	customerID, _ := cmd.Flags().GetString("link-aws-account")
	if customerID != "" {
		err = sdk.LinkAWSAccount(C.EnclaveHost, authToken, customerID)
		if err != nil {
			return err
		}
	}

	fmt.Println("Congratulations, you're all set!")
	return nil
}

func persistTokenResponse(t *oauth2.Token) error {
	var tok struct {
		*oauth2.Token
		IDToken string `json:"id_token,omitempty"`
	}

	idTok, ok := t.Extra("id_token").(string)
	if !ok {
		fmt.Println("no id token")
	}
	tok.Token = t
	tok.IDToken = idTok

	authJSON, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}

	err = sdk.PersistFile(C.LocalConfigDir, C.LocalAuthFileName, authJSON)
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
