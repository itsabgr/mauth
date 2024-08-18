package providers

import (
	"context"
)

type Provider interface {
	Name() string
	Enable(id, secret, redirect string)
	Enabled() bool
	AuthCodeURL(state string) (link string)
	Exchange(ctx context.Context, state, code string) (token string, err error)
	ReadEmails(ctx context.Context, token string) ([]string, error)
}
