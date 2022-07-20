package entities

type EncryptResponse struct {
	Value string `json:"value"'`
}

type EncryptRequest struct {
	AuthToken string `json:"auth_token"`
	Data      string `json:"data"`
}
