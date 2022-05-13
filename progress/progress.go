package progress

import "io"

type Reader struct {
	io.Reader
	Size     int64
	Reporter func(progress float64)

	b int64
}

func (pr *Reader) Read(p []byte) (n int, err error) {
	n, err = pr.Reader.Read(p)
	pr.b += int64(n)
	progress := float64(pr.b) / float64(pr.Size)
	pr.Reporter(progress)
	return
}
