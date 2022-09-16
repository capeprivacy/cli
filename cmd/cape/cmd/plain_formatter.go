package cmd

import (
	"bytes"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type PlainFormatter struct{}

func (f *PlainFormatter) Format(entry *log.Entry) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, entry.Message)
	for k, v := range entry.Data {
		fmt.Fprintf(&buf, "%s ➜ %s\n", munge(k), v)
	}
	return buf.Bytes(), nil
}

func munge(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	return cases.Title(language.English).String(s)
}
