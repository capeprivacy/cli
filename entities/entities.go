package entities

import (
	"fmt"
	"time"
)

type StartRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce         []byte           `json:"nonce"`
	FunctionToken string           `json:"function_token,omitempty"`
	Metadata      FunctionMetadata `json:"metadata,omitempty"`
}

type RunRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce     []byte `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type DeployRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce     []byte `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type FunctionInfo struct {
	FunctionTokenPublicKey string `json:"function_token_pk"`
	FunctionName           string `json:"function_name"`
}

type FunctionMetadata struct {
	FunctionAuthenticationType string `json:"function_authentication_type"`
}

type TestRequest struct {
	Nonce     []byte `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type RunJobsResponse struct {
	FunctionID ID   `json:"function_id"`
	Done       bool `json:"done"`
}

type SetDeploymentIDRequest struct {
	ID string `json:"id"`
}

type AttestationWrapper struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

type RunResults struct {
	Type    string `json:"type"`
	Message []byte `json:"message"`
}

type AuthenticationType string

func (a AuthenticationType) Validate() error {
	switch a {
	case AuthenticationTypeUserToken, AuthenticationTypeFunctionToken:
		return nil
	default:
		return fmt.Errorf("invalid authentication type: %s", a)
	}
}

func (a AuthenticationType) String() string {
	return string(a)
}

const (
	AuthenticationTypeUserToken     AuthenticationType = "user_token"
	AuthenticationTypeFunctionToken AuthenticationType = "functiontoken"
)

type FunctionAuth struct {
	Token string
	Type  AuthenticationType
}

type Deployment struct {
	ID        ID        `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
