package render

import "context"

type ctxKey struct{}

// WithCtx returns a copy of ctx with r associated.
func WithCtx(ctx context.Context, r Renderer) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// Ctx returns the Renderer associated with the ctx. If no logger
// is associated, DefaultContextRenderer is returned, unless DefaultContextRenderer
// is nil, in which case a Print renderer is returned.
func Ctx(ctx context.Context) Renderer {
	if r, ok := ctx.Value(ctxKey{}).(Renderer); ok {
		return r
	} else if r = DefaultContextRenderer; r != nil {
		return r
	}
	return Print{}
}

var DefaultContextRenderer Renderer
