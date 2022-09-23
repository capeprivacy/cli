package sdk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"

	"github.com/capeprivacy/cli/entities"
)

type FunctionIDRequest struct {
	URL          string
	FunctionName string
}

func GetFunctionID(functionReq FunctionIDRequest) (string, error) {
	endpoint := fmt.Sprintf("%s/v1/function?name=%s", functionReq.URL, functionReq.FunctionName)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to receive functionID %w", err)
	}

	if res.StatusCode != 200 {
		return "", fmt.Errorf("expected 200, got server response code %d", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.New("could not read response body")
	}

	// read the function id
	var deployment entities.Deployment
	err = json.Unmarshal(body, &deployment)
	if err != nil {
		return "", errors.New("malformed body in response")
	}
	return deployment.ID.String(), nil
}
