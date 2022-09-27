package render

import (
	"context"
	"testing"
)

func TestWithCtx(t *testing.T) {
	r := NewTemplate("foo")
	ctx := WithCtx(context.Background(), r)
	r2 := Ctx(ctx)
	if got, want := r2, r; got != want {
		t.Errorf("Ctx returned incorrect Renderer;\n\tgot  %#v\n\twant %#v", got, want)
	}
}

func TestWithCtxDefault(t *testing.T) {
	r := Print{}
	r2 := Ctx(context.Background())
	if got, want := r2, r; got != want {
		t.Errorf("Ctx returned incorrect Renderer;\n\tgot  %#v\n\twant %#v", got, want)
	}
}

func TestWithCtxDefaultContextRenderer(t *testing.T) {
	r := NewTemplate("itsa me")
	DefaultContextRenderer = r

	r2 := Ctx(context.Background())
	if got, want := r2, r; got != want {
		t.Errorf("Ctx returned incorrect Renderer;\n\tgot  %#v\n\twant %#v", got, want)
	}
}
