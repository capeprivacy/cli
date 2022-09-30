package render

import (
	"encoding/json"
	"fmt"
	"io"
	"text/template"
)

// A Render formats the provided value and outputs it to the writer.
type Renderer interface {
	Render(w io.Writer, value any) error
}

// MustRender calls `r.Render()` and panics if a non-nil error is returned
func MustRender(r Renderer, w io.Writer, value any) {
	if err := r.Render(w, value); err != nil {
		panic(err)
	}
}

// JSON is a renderers that marshals the value to JSON
type JSON struct{}

// Render implements the Renderer interface
func (j JSON) Render(w io.Writer, value any) error {
	return json.NewEncoder(w).Encode(value)
}

// Print prints the value with the default format for the value's type.
type Print struct{}

// Render implements the Renderer interface
func (p Print) Render(w io.Writer, value any) error {
	_, err := fmt.Fprint(w, value)
	return err
}

// Template renders a template with the provided value
type Template struct {
	tmpl string
}

// NewTemplate creates a Template with the given string template
func NewTemplate(tmpl string) *Template {
	return &Template{
		tmpl: tmpl,
	}
}

// Render implements the Renderer interface
func (t *Template) Render(w io.Writer, value any) error {
	tmpl, err := template.New("tmpl").Parse(t.tmpl)
	if err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	if err = tmpl.Execute(w, value); err != nil {
		return fmt.Errorf("error rendering template: %w", err)
	}

	return nil
}
