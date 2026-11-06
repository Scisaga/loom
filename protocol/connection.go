package protocol

import "context"

// Connection is ephemeral execution data. Its Policy is filled from an
// authenticated runtime binding, never accepted as a request-supplied grant.
type Connection struct {
	PolicyID string
	Path     PathContext
}
type connectionKey struct{}

func WithConnection(ctx context.Context, value Connection) context.Context {
	value.Path.Visited = append([]string{}, value.Path.Visited...)
	return context.WithValue(ctx, connectionKey{}, value)
}
func ConnectionFrom(ctx context.Context) (Connection, bool) {
	value, ok := ctx.Value(connectionKey{}).(Connection)
	if ok {
		value.Path.Visited = append([]string{}, value.Path.Visited...)
	}
	return value, ok
}
