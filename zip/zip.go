package zip

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Walker(w *zip.Writer, zipRoot string) filepath.WalkFunc {
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

	if err := filepath.Walk(input, Walker(w, zipRoot)); err != nil {
		return nil, fmt.Errorf("zipping directory failed: %w", err)
	}

	// Explicitly close now so that the bytes are flushed and
	// available in buf.Bytes() below.
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zipping directory failed: %w", err)
	}

	return buf.Bytes(), nil
}
