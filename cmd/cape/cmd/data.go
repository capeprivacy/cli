package cmd

import (
	"encoding/csv"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"math/rand"
	"os"
	"strconv"
)

// generate sample data to use for testing cape
var sampleCmd = &cobra.Command{
	Use:   "sample <format> <bytes> <filename>",
	Short: "Generate sample data for testing your function with Cape",
	Example: `
# Generate a single string in a text file
$ cape sample text 128 testdata.txt

# Generate a CSV file of decimal values with 3 columns
$ cape sample csv 128000 testdata.csv -t decimal -l 3
	`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			err := cmd.Usage()
			if err != nil {
				return err
			}
			return nil
		}

		err := sample(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(sampleCmd)

	sampleCmd.PersistentFlags().StringP("type", "t", "decimal", "for CSV output, the data type for the cell values (one of: string, int, decimal)")
	sampleCmd.PersistentFlags().IntP("columns", "l", 10, "for CSV output, the number of columns")
}

func sample(cmd *cobra.Command, args []string) error {
	if len(args) != 3 {
		return errors.New("please provide output format, data size, and file name")
	}
	format := args[0]
	bytes, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("error parsing input: %w", err)
	}
	fileName := args[2]

	switch format {
	case "text":
		err := writeText(fileName, randomText(bytes))
		if err != nil {
			return err
		}
	case "csv":
		cols, err := cmd.Flags().GetInt("columns")
		if err != nil {
			return UserError{Msg: "error retrieving columns flag", Err: err}
		}
		t, err := cmd.Flags().GetString("type")
		if err != nil {
			return UserError{Msg: "error retrieving type flag", Err: err}
		}

		var valueFunc func() string
		switch t {
		case "string":
			valueFunc = fixedRandomText
		case "int":
			valueFunc = func() string {
				return strconv.FormatInt(rand.Int63(), 10)
			}
		case "decimal":
			valueFunc = func() string {
				return strconv.FormatFloat(rand.Float64(), 'f', -1, 32)
			}
		default:
			return UserError{Msg: "CSV value type must be one of: string, int, decimal"}
		}

		rows := randomCSV(cols, bytes, valueFunc)
		err = writeCSV(fileName, rows)
		if err != nil {
			return err
		}
	default:
		return UserError{Msg: "file format must be one of: text, csv"}
	}

	return nil
}

func randomCSV(cols int, size int, valueFunc func() string) [][]string {
	headers := make([]string, cols)
	for i := range headers {
		headers[i] = fixedRandomText()
	}
	totalSize := 8 * (cols + 1)

	data := [][]string{headers}
	for totalSize < size {
		row := make([]string, cols)
		for i := range row {
			row[i] = valueFunc()
			totalSize += len(row[i]) + 1
		}
		data = append(data, row)
	}

	return data
}

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_1234567890"

// randomText returns string data of the given size in bytes
func randomText(bytes int) []byte {
	b := make([]byte, bytes)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return b
}

// fixedRandomText returns a random string of length 8
func fixedRandomText() string {
	return string(randomText(8))
}

func writeText(fileName string, data []byte) error {
	f, err := os.Create(fileName)
	defer f.Close()

	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err != nil {
		return err
	}

	log.Infof("wrote file '%s'", fileName)
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("error reading file info: %w", err)
	}
	log.Infof("file size: %d bytes", fi.Size())

	return nil
}

func writeCSV(fileName string, data [][]string) error {
	f, err := os.Create(fileName)
	defer f.Close()

	if err != nil {
		return err
	}

	w := csv.NewWriter(f)

	for _, row := range data {
		_ = w.Write(row)
	}
	w.Flush()

	log.Infof("wrote file '%s'", fileName)
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("error reading file info: %w", err)
	}
	log.Infof("file size: %d bytes", fi.Size())

	return nil
}
