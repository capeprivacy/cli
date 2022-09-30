package render

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"text/template"
)

func TestRender(t *testing.T) {
	tests := []struct {
		name string
		r    Renderer
		in   any
		out  string
	}{
		{
			name: "JSON - struct",
			r:    &JSON{},
			in: struct {
				Foo string `json:"foo"`
				Bar string `json:"bar"`
			}{
				Foo: "I'm foo!",
				Bar: "And I'm bar!",
			},
			out: `{"foo":"I'm foo!","bar":"And I'm bar!"}
`,
		},
		{
			name: "JSON - map",
			r:    &JSON{},
			in: map[string]string{
				"foo": "I'm foo!",
				"bar": "And I'm bar!",
			},
			out: `{"bar":"And I'm bar!","foo":"I'm foo!"}
`,
		},
		{
			name: "Print",
			r:    Print{},
			in: map[string]string{
				"foo": "I'm foo!",
				"bar": "And I'm bar!",
			},
			out: "map[bar:And I'm bar! foo:I'm foo!]",
		},
		{
			name: "Template",
			r:    NewTemplate("Foo: {{ .Foo }} - Bar: {{ .Bar }}"),
			in: struct {
				Foo string `json:"foo"`
				Bar string `json:"bar"`
			}{
				Foo: "I'm foo!",
				Bar: "And I'm bar!",
			},
			out: "Foo: I'm foo! - Bar: And I'm bar!",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf strings.Builder
			MustRender(test.r, &buf, test.in)
			if got, want := buf.String(), test.out; got != want {
				t.Errorf("value rendered incorrectly: got %q want %q", got, want)
			}
		})
	}
}

func TestTemplateErr(t *testing.T) {
	tests := []struct {
		name string
		r    Renderer
		in   any
		out  error
	}{
		{
			name: "bad template",
			r:    NewTemplate("{{ {{ }}"),
			in:   map[string]string{"does_not_matter": "it's a no-op"},
			out:  fmt.Errorf("invalid template: %w", errors.New("template: tmpl:1: unexpected \"{\" in command")),
		},
		{
			name: "failed to render",
			r:    NewTemplate("{{ .NotAField }}"),
			in: struct {
				AField string
			}{
				AField: "further afield",
			},
			out: fmt.Errorf(
				"error rendering template: %w",
				template.ExecError{
					Name: "tmpl",
					Err:  errors.New("template: tmpl:1:3: executing \"tmpl\" at <.NotAField>: can't evaluate field NotAField in type struct { AField string }"),
				},
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf strings.Builder
			if got, want := test.r.Render(&buf, test.in), test.out; !reflect.DeepEqual(got, want) {
				t.Errorf("unexpected error returned;\n\tgot  %#v\n\twant %#v", got, want)
			}
		})
	}
}

func TestPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustRender did not panic")
		}
	}()

	r := NewTemplate("{{ {{ }}")
	var buf strings.Builder
	MustRender(r, &buf, map[string]string{"spooky": "season"})
}
