package server

import (
	"context"
)

// contextWithUser adds a username to the context for testing authenticated endpoints
func contextWithUser(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, userKey, username)
}
