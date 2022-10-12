package sdk2

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/capeprivacy/cli/entities"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// TODO: where does this belong, file-wise?
const capeURL = "https://app.capeprivacy.com"

type FunctionIDRequest struct {
	UserName     string
	FunctionName string
	URL          string
	AuthToken    string
}

type errorMsg struct {
	Message string `json:"message"`
}

func GetFunctionID(function string, capeURL string, authToken string) (string, error) {
	if isValidFunctionID(function) {
		return function, nil
	}

	if !strings.Contains(function, "/") {
		return "", fmt.Errorf("please provide a functionID or a function name of format <githubUser>/<functionName>")
	}

	userName, functionName, err := splitFunctionName(function)
	if err != nil {
		return "", fmt.Errorf("%s, please provide a function name of format <githubUser>/<functionName>", err)
	}
	u, err := url.Parse(capeURL)
	if err != nil {
		return "", err
	}
	// If the user called w/ `cape run my/fn --url wss://.... we will want to change the scheme to HTTP(s) for this call
	if u.Scheme == "ws" {
		u.Scheme = "http"
	}

	if u.Scheme == "wss" {
		u.Scheme = "https"
	}

	r := FunctionIDRequest{
		UserName:     userName,
		FunctionName: functionName,
		URL:          u.String(),
		AuthToken:    authToken,
	}

	functionID, err := getFunctionID(r)
	if err != nil {
		return "", fmt.Errorf("error retrieving function: %w", err)
	}
	return functionID, nil
}

func isValidFunctionID(functionID string) bool {
	// an alphanumeric string of length 22 is considered a syntactically correct functionID
	return regexp.MustCompile(`^[a-zA-Z0-9]{22}$`).MatchString(functionID)
}

func splitFunctionName(function string) (string, string, error) {
	userName, functionName, found := strings.Cut(function, "/")

	if !found {
		return "", "", errors.New("no '/' in function name")
	}

	if userName == "" {
		return "", functionName, errors.New("empty username")
	}

	if functionName == "" {
		return userName, "", errors.New("empty function name")
	}
	return userName, functionName, nil
}

func getFunctionID(functionReq FunctionIDRequest) (string, error) {
	if functionReq.URL == "" {
		functionReq.URL = capeURL
	}

	if functionReq.UserName == "" {
		return "", fmt.Errorf("please provide a username")
	}

	if functionReq.FunctionName == "" {
		return "", fmt.Errorf("please provide a function name")
	}

	endpoint := fmt.Sprintf("%s/v1/%s/function/%s", functionReq.URL, functionReq.UserName, functionReq.FunctionName)
	req, err := http.NewRequest("GET", endpoint, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", functionReq.AuthToken))
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to receive functionID %w", err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.New("could not read response body")
	}

	if res.StatusCode != http.StatusOK {
		// return the error message from supervisor
		var e errorMsg
		err = json.Unmarshal(body, &e)
		if err != nil {
			return "", fmt.Errorf("couldn't unmarshal json")
		}
		return "", fmt.Errorf("HTTP Error: %d %s", res.StatusCode, e.Message)
	}

	// read the function id
	var deployment entities.DeploymentName
	err = json.Unmarshal(body, &deployment)
	if err != nil {
		return "", errors.New("malformed body in response")
	}
	return deployment.ID.String(), nil
}
