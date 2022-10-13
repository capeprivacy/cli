package sdk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"

	"github.com/capeprivacy/cli/entities"
)

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

func GetFunctionID(functionReq FunctionIDRequest) (string, error) {
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
		if res.StatusCode == http.StatusBadGateway {
			return "", fmt.Errorf("could not lookup function, received %d from server", res.StatusCode)
		}

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
