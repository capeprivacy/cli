package cmd

import (
	"errors"
	"fmt"
	"net/http"
)

type ErrorMsg struct {
	ErrorMsg string `json:"error"`
}

func (e ErrorMsg) Error() string {
	return e.ErrorMsg
}

var ErrUnauthorized = errors.New("unauthorized: authentication required")

// httpError returns a generic error for the given http status code
func httpError(status int) error {
	return fmt.Errorf("%d %s", status, http.StatusText(status))
}
