package providers

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
	auth "golang.org/x/oauth2/google"
	googleOauth2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

func init() {
	Register(new(Google))
}

var _ Provider = &Google{}

type Google struct {
	enabled              bool
	id, secret, redirect string
}

func (g *Google) Exchange(ctx context.Context, state, code string) (token string, err error) {
	if len(code) == 0 {
		return "", errors.New("no code")
	}
	tkn, err := g.config().Exchange(ctx, code)
	if err != nil {
		return "", err
	}
	return tkn.AccessToken, nil
}

func (g *Google) Enabled() bool {
	return g.enabled
}
func (g *Google) Name() string {
	return "google"
}

func (g *Google) Enable(id, secret, redirect string) {
	g.redirect = redirect
	g.secret = secret
	g.id = id
	g.enabled = true
}
func (g *Google) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.id,
		ClientSecret: g.secret,
		Endpoint:     auth.Endpoint,
		RedirectURL:  g.redirect,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	}
}

func (g *Google) AuthCodeURL(state string) string {
	return g.config().AuthCodeURL(state)
}

func (g *Google) ReadEmails(ctx context.Context, tokenStr string) ([]string, error) {
	token := &oauth2.Token{AccessToken: tokenStr}
	serv, err := googleOauth2.NewService(ctx, option.WithScopes(), option.WithTokenSource(g.config().TokenSource(ctx, token)))
	if err != nil {
		return nil, err
	}
	info, err := serv.Userinfo.Get().Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return []string{info.Email}, nil
}
