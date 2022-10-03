package cmd

import "testing"

func Test_isValidFunctionID(t *testing.T) {
	tests := []struct {
		name       string
		functionID string
		want       bool
	}{
		{
			"valid functionID regex",
			"hivhkjYPQCWhyP4YaNcrnM",
			true,
		},
		{
			"invalid functionID regex",
			"hivhkjYPQCWhyP/aNc",
			false,
		},
		{
			"functionID too short",
			"hivhkjYPQCWhyP4",
			false,
		},
		{
			"functionID too long",
			"hivhkjYPQCWhyP4YaNcrnMhivhkjYPQCWhyP4",
			false,
		},
		{
			"invalid functionID length",
			"12345",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidFunctionID(tt.functionID); got != tt.want {
				t.Errorf("isValidFunctionID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_splitFunctionName(t *testing.T) {
	tests := []struct {
		name             string
		function         string
		wantUserName     string
		wantFunctionName string
		wantErr          bool
	}{
		{
			"valid callable function",
			"git-user123/coolfunction",
			"git-user123",
			"coolfunction",
			false,
		},
		{
			"functionName missing",
			"git-user123/",
			"git-user123",
			"",
			true,
		},
		{
			"username missing",
			"/coolfunction",
			"",
			"coolfunction",
			true,
		},
		{
			"/ missing",
			"waitwhat",
			"",
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userName, functionName, err := splitFunctionName(tt.function)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitFunctionName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if userName != tt.wantUserName {
				t.Errorf("expected userName %v, got = %v", tt.wantUserName, userName)
			}
			if functionName != tt.wantFunctionName {
				t.Errorf("expected functionName %v, got1 = %v", tt.wantFunctionName, functionName)
			}
		})
	}
}
