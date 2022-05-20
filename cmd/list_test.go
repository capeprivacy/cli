package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	gHTTP "github.com/capeprivacy/go-kit/http"
)

func TestList(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/v1/list", func(w http.ResponseWriter, r *http.Request) {
		deployments := []DeploymentName{
			{"abc123", "cool-func"},
			{"abc456", "cool-func2"},
		}

		gHTTP.RespondWithJSON(w, http.StatusOK, deployments)
	})
	s := httptest.NewServer(r)
	defer s.Close()

	b := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetOut(b)
	cmd.SetArgs([]string{"list", "-u", s.URL})

	if err := cmd.Execute(); err != nil {
		t.Error(err)
	}

	tbl := b.String()
	sp := strings.Split(tbl, "|")

	parsed := []string{}
	for _, str := range sp {
		if !strings.Contains(str, "+-") && str != "\n" {
			fmt.Printf("hello! %s hello\n", str)
			parsed = append(parsed, strings.ReplaceAll(strings.ReplaceAll(str, " ", ""), "\n", ""))
		}
	}

	if got, want := parsed, []string{"DEPLOYMENT_ID", "FUNCTION_NAME", "abc123", "cool-func", "abc456", "cool-func2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected table headers and values. got: %s, want: %s", got, want)
	}
}
