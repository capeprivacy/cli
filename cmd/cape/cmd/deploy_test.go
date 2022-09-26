package cmd

import "testing"

func Test_getName(t *testing.T) {
	for _, tt := range []struct {
		name          string
		functionInput string
		nameFlag      string
		want          string
	}{
		{
			name:          "function name from flag",
			functionInput: "echo",
			nameFlag:      "e",
			want:          "e",
		},
		{
			name:          "function name from simple zip",
			functionInput: "echo.zip",
			want:          "echo",
		},
		{
			name:          "function name from zip in named dir",
			functionInput: "functions/echo.zip",
			want:          "echo",
		},
		{
			name:          "function name from zip in ..",
			functionInput: "../echo.zip",
			want:          "echo",
		},
		{
			name:          "function name from zip in .",
			functionInput: "./echo.zip",
			want:          "echo",
		},
		{
			name:          "function name from simple dir without trailing /",
			functionInput: "echo",
			want:          "echo",
		},
		{
			name:          "function name from simple dir with trailing /",
			functionInput: "echo/",
			want:          "echo",
		},
		{
			name:          "function name from dir in named dir",
			functionInput: "functions/echo",
			want:          "echo",
		},
		{
			name:          "function name from dir in ..",
			functionInput: "../echo",
			want:          "echo",
		},
		{
			name:          "function name from dir in .",
			functionInput: "./echo",
			want:          "echo",
		},
		{
			name:          "function name from dir in named dir with trailing /",
			functionInput: "functions/echo/",
			want:          "echo",
		},
		{
			name:          "function name from dir in .. with trailing /",
			functionInput: "../echo/",
			want:          "echo",
		},
		{
			name:          "function name from dir in . with trailing /",
			functionInput: "./echo/",
			want:          "echo",
		},
		{
			name:          "known edge case: ..",
			functionInput: "..",
			want:          "",
		},
		{
			name:          "known edge case: .",
			functionInput: ".",
			want:          "",
		},
		{
			name:          "known edge case: /",
			functionInput: "/",
			want:          "/",
		},
		{
			name:          "known edge case: ~",
			functionInput: "~",
			want:          "~",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := getName(tt.functionInput, tt.nameFlag); got != tt.want {
				t.Errorf("getName() = %v, want %v", got, tt.want)
			}
		})
	}
}
