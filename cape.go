package cli

type VerifiedResults struct {
	InputSig  []byte `json:"input_signature"`
	FuncSig   []byte `json:"function_signature"`
	OutputSig []byte `json:"output_signature"`
}

type RunResult struct {
	// TODO -- Remove type??
	Type            string          `json:"type"`
	Message         []byte          `json:"message"`
	VerifiedResults VerifiedResults `json:"verified_results"`
	SignedResults   []byte          `json:"signed_results"`
}
