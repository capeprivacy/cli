package zip

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func walker(w *zip.Writer) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		path = filepath.ToSlash(path)

		f, err := w.Create(path)
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}

		return nil
	}
}

func Create(input string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipRoot := filepath.Base(input)
	w := zip.NewWriter(buf)

	savedDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// change dir to just above zip root incase we're many nested directories in
	err = os.Chdir(filepath.Join(input, ".."))
	if err != nil {
		return nil, err
	}
	defer os.Chdir(savedDir) // nolint: errcheck

	if err := filepath.Walk(zipRoot, walker(w)); err != nil {
		return nil, fmt.Errorf("zipping directory failed: %w", err)
	}

	// Explicitly close now so that the bytes are flushed and
	// available in buf.Bytes() below.
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zipping directory failed: %w", err)
	}

	return buf.Bytes(), nil
}
