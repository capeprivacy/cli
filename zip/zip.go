package zip

import (
	"archive/zip"
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

		basePath := filepath.Base(path)

		f, err := w.Create(filepath.Join(zipRoot, basePath))
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
