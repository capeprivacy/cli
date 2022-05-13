package zip

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalker(t *testing.T) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	dir := t.TempDir()
	f, err := os.Create(dir + "/file.py")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	zipRoot := filepath.Base(dir)

	err = filepath.Walk(dir, Walker(w, zipRoot))
	if err != nil {
		t.Fatal(err)
	}

	w.Close()

	byRead := bytes.NewReader(buf.Bytes())
	r, err := zip.NewReader(byRead, int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	if len(r.File) != 1 {
		t.Fatalf("there must be one file in zip but there are %d", len(r.File))
	}

	expectedFileName := "001/file.py"
	// we make this in a temp dir so the which will have a wonky prefix
	if !strings.HasSuffix(r.File[0].Name, "001/file.py") {
		t.Fatalf("expected %s got %s", expectedFileName, r.File[0].Name)
	}
}
