package entities

import "github.com/capeprivacy/go-kit/id"

type StartRequest struct {
	// Nonce is used by the client to verify the nonce received back in
	// the attestation doc
	Nonce         []byte           `json:"nonce"`
	AuthToken     string           `json:"auth_token"`
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

type FunctionPublicKey struct {
	FunctionTokenPublicKey string `json:"function_token_pk"`
}

type FunctionMetadata struct {
	FunctionAuthenticationType string `json:"function_authentication_type"`
}

type TestRequest struct {
	Nonce     []byte `json:"nonce"`
	AuthToken string `json:"auth_token"`
}

type RunJobsResponse struct {
	FunctionID *id.ID `json:"function_id"`
	Done       bool   `json:"done"`
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
