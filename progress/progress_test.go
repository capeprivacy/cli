package progress

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestProgress(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// force everything to be read to fill progress
		buf := make([]byte, 1024)
		for {
			_, err := r.Body.Read(buf)
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
			}
		}

		w.WriteHeader(http.StatusCreated)
	}))
	defer s.Close()

	f, err := os.Open("./testdata/isprime.zip")
	if err != nil {
		t.Error(err)
	}

	fi, err := f.Stat()
	if err != nil {
		t.Error(err)
	}

	size := fi.Size()

	var progress float64 = 0
	pr := &Reader{Reader: f, Size: size, Reporter: func(p float64) {
		if p < progress {
			t.Errorf("progress should increase towards 1, got %f, previous: %f", p, progress)
		}

		progress = p
	}}

	_, err = http.Post(s.URL, "application/zip", pr)
	if err != nil {
		t.Error(err)
	}

	if progress != 1 {
		t.Errorf("progress didn't end up at 1: %f", progress)
	}
}
