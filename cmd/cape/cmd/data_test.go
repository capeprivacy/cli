package cmd

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// nolint:gocognit
func TestSample(t *testing.T) {
	for _, tt := range []struct {
		name        string
		fileType    string
		size        string
		fileName    string
		csvType     string
		csvCols     string
		extraArg    bool
		errContains string
	}{
		{
			name:        "too few args",
			errContains: "please provide output format, data size, and file name",
		},
		{
			name:        "too many args",
			fileType:    "text",
			size:        "512",
			fileName:    "test.txt",
			extraArg:    true,
			errContains: "please provide output format, data size, and file name",
		},
		{
			name:        "invalid file size",
			fileType:    "text",
			size:        "foo",
			fileName:    "test.txt",
			errContains: "error parsing input",
		},
		{
			name:        "invalid file type",
			fileType:    "wav",
			size:        "512",
			fileName:    "test.wav",
			errContains: "file format must be one of: text, csv",
		},
		{
			name:     "success: text",
			fileType: "text",
			size:     "512",
			fileName: "test.txt",
		},
		{
			name:     "success: csv with defaults (decimal)",
			fileType: "csv",
			size:     "2048",
			fileName: "test.csv",
		},
		{
			name:     "success: csv with string values",
			fileType: "csv",
			size:     "2048",
			fileName: "test.csv",
			csvType:  "string",
			csvCols:  "5",
		},
		{
			name:     "success: csv with int values",
			fileType: "csv",
			size:     "2048",
			fileName: "test.csv",
			csvType:  "int",
			csvCols:  "5",
		},
		{
			name:        "invalid csv column value",
			fileType:    "csv",
			size:        "2048",
			fileName:    "test.csv",
			csvCols:     "foo",
			errContains: "invalid argument",
		},
		{
			name:        "non-positive csv column value",
			fileType:    "csv",
			size:        "2048",
			fileName:    "test.csv",
			csvCols:     "0",
			errContains: "number of columns must be positive",
		},
		{
			name:        "invalid csv value type",
			fileType:    "csv",
			size:        "2048",
			fileName:    "test.csv",
			csvType:     "beans",
			csvCols:     "5",
			errContains: "CSV value type must be one of: string, int, decimal",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd, stdout, _ := getCmd()
			args := []string{"sample"}
			if tt.fileType != "" {
				args = append(args, tt.fileType)
			}
			if tt.size != "" {
				args = append(args, tt.size)
			}
			if tt.fileName != "" {
				args = append(args, tt.fileName)
			}
			if tt.extraArg {
				args = append(args, "hi!")
			}
			if tt.csvType != "" {
				args = append(args, "--type", tt.csvType)
			}
			if tt.csvCols != "" {
				args = append(args, "--columns", tt.csvCols)
			}
			cmd.SetArgs(args)

			err := cmd.Execute()
			if tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing '%s', got: %v", tt.errContains, err)
				}
				if _, ok := err.(UserError); ok && !strings.Contains(stdout.String(), "Usage:") {
					t.Fatalf("output did not contain usage")
				}
				return
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			defer func() {
				err := os.Remove(tt.fileName)
				if err != nil {
					t.Fatalf("unable to remove file: %s", tt.fileName)
				}
			}()

			f, err := os.Open(tt.fileName)
			if err != nil {
				t.Fatal("error opening file")
			}
			defer func() {
				err := f.Close()
				if err != nil {
					t.Fatal("error closing file")
				}
			}()
			i, err := f.Stat()
			if err != nil {
				t.Fatal("error getting file info")
			}
			wantSize, err := strconv.Atoi(tt.size)
			if err != nil {
				t.Fatal("error parsing file size")
			}
			if i.Size() < int64(wantSize) {
				t.Fatalf("wanted file of size %d bytes, output file was size %d bytes", wantSize, i.Size())
			}
		})
	}
}
