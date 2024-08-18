package providers

import (
	"context"
	"errors"
	"github.com/google/go-github/v63/github"
	"golang.org/x/oauth2"
	auth "golang.org/x/oauth2/github"
	"net/http"
)

func init() {
	Register(new(Github))
}

var _ Provider = &Github{}

type Github struct {
	enabled              bool
	id, secret, redirect string
}

func (g *Github) Exchange(ctx context.Context, state, code string) (token string, err error) {
	if len(code) == 0 {
		return "", errors.New("no code")
	}
	tkn, err := g.config().Exchange(ctx, code)
	if err != nil {
		return "", err
	}
	return tkn.AccessToken, nil
}

func (g *Github) Enabled() bool {
	return g.enabled
}
func (g *Github) Name() string {
	return "github"
}

func (g *Github) Enable(id, secret, redirect string) {
	g.redirect = redirect
	g.secret = secret
	g.id = id
	g.enabled = true
}
func (g *Github) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.id,
		ClientSecret: g.secret,
		Endpoint:     auth.Endpoint,
		RedirectURL:  g.redirect,
		Scopes:       []string{"user:email"},
	}
}
func (g *Github) AuthCodeURL(state string) string {
	return g.config().AuthCodeURL(state)
}
func (g *Github) ReadEmails(ctx context.Context, token string) ([]string, error) {
	emails, _, err := github.NewClient(http.DefaultClient).WithAuthToken(token).Users.ListEmails(ctx, &github.ListOptions{
		Page:    0,
		PerPage: 10,
	})
	if err != nil {
		return nil, err
	}
	list := make([]string, 0, 10)
	for _, email := range emails {
		if !email.GetVerified() {
			continue
		}
		list = append(list, email.GetEmail())
	}
	return list, nil
}
