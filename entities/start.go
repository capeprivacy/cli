package entities

type StartRequest struct {
	Nonce     string `json:"nonce"`
	AuthToken string `json:"auth_token"`
}
