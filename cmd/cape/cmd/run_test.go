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
			"invalid functionID length",
			"hivhkjYPQCWhyP4YaNc",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userName, functionName, err := splitFunctionName(tt.function)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitFunctionName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if userName != tt.wantUserName {
				t.Errorf("splitFunctionName() got = %v, want %v", userName, tt.wantUserName)
			}
			if functionName != tt.wantFunctionName {
				t.Errorf("splitFunctionName() got1 = %v, want %v", functionName, tt.wantFunctionName)
			}
		})
	}
}
