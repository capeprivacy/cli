package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// TODO: Add stage specific values.
var hostname = "https://maestro-dev.us.auth0.com"
var clientID = "yQnobkOr1pvdDAyXwNojkNV2IPbNfXxx"
var audience = "https://newdemo.capeprivacy.com/v1/"

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to cape application",
	Run:   login,
}

func init() {
	rootCmd.AddCommand(loginCmd)
}

func login(cmd *cobra.Command, args []string) {
	newDeviceCode()
}

type DeviceCodeResponse struct {
	VerificationURIComplete string `json:"verification_uri_complete"`
	UserCode                string `json:"user_code"`
}

func newDeviceCode() {
	deviceCodeURL := fmt.Sprintf("%s/oauth/device/code", hostname)
	payloadStr := fmt.Sprintf("client_id=%s&scope=openid%%20profile%%20email&audience=%s", clientID, audience)
	req, err := http.NewRequest("POST", deviceCodeURL, strings.NewReader(payloadStr))
	if err != nil {
		panic(fmt.Sprintf("unable to login to cape %s", err))
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(fmt.Sprintf("unable to login to cape %s", err))
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(fmt.Sprintf("unable to login to cape %s", err))
	}

	if res.StatusCode != 200 {
		panic(fmt.Sprintf("unable to login to cape, error: %s", res.Status))
	}

	response := DeviceCodeResponse{}
	err = json.Unmarshal(body, &response)

	if err != nil || len(response.VerificationURIComplete) == 0 {
		panic("unable to login to cape, unknown error")
	}

	fmt.Printf("Your CLI confirmation code is: %s\n", response.UserCode)
	openbrowser(response.VerificationURIComplete)
}

// Taken from GIST: https://gist.github.com/hyg/9c4afcd91fe24316cbf0
func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}
