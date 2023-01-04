package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func LinkAWSAccount(url string, token string, customerID string) error {
	endpoint := fmt.Sprintf("%s/v1/marketplace_link_account", url)

	body := struct {
		CustomerID string `json:"customer_id"`
	}{
		CustomerID: customerID,
	}

	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(b))

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusCreated {
		if res.StatusCode == http.StatusBadGateway {
			return fmt.Errorf("could not link accounts, received %d from server", res.StatusCode)
		}

		// return the error message from supervisor
		var e errorMsg
		err = json.NewDecoder(res.Body).Decode(&e)
		if err != nil {
			return fmt.Errorf("couldn't unmarshal json")
		}
		return fmt.Errorf("HTTP Error: %d %s", res.StatusCode, e.Message)
	}

	return nil
}
