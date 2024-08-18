package mauth

import (
	"aidanwoods.dev/go-paseto"
	"context"
	"errors"
	"mauth/providers"
	"net/url"
)

type Authenticator struct {
	providers map[string]providers.Provider
	secret    paseto.V4SymmetricKey
}

func NewAuthenticator(providers map[string]providers.Provider, secret paseto.V4SymmetricKey) *Authenticator {
	return &Authenticator{
		providers: providers,
		secret:    secret,
	}
}

type AuthenticationOption struct {
	Name string
	Link string
}

type Authentication struct {
	Options map[string]AuthenticationOption
}

func (a *Authenticator) NewAuthentication(redirect url.URL) (*Authentication, error) {
	if err := ValidateRedirectionURI(&redirect); err != nil {
		return nil, err
	}

	auth := &Authentication{
		Options: make(map[string]AuthenticationOption, len(a.providers)),
	}
	state := &State{
		RedirectURI: redirect.String(), //app should not be aware of which option is selected
	}
	for name, provider := range a.providers {
		if !provider.Enabled() {
			continue
		}
		state.Provider = name
		stateString := state.Encrypt(a.secret)
		link := provider.AuthCodeURL(stateString)
		auth.Options[name] = AuthenticationOption{
			Name: provider.Name(),
			Link: link,
		}
	}
	return auth, nil
}

func (a *Authenticator) ReadEmails(ctx context.Context, state *State, code string) (emails []string, err error) {
	if _, err = ValidateRedirectionString(state.RedirectURI); err != nil {
		return nil, err
	}
	provider, _ := a.providers[state.Provider]
	if provider == nil || !provider.Enabled() {
		return nil, errors.New("provider not found")
	}
	tkn, err := provider.Exchange(ctx, state.Encrypt(a.secret), code)
	if err != nil {
		return nil, err
	}
	emails, err = provider.ReadEmails(ctx, tkn)
	if err != nil {
		return nil, err
	}
	return emails, nil
}

func ValidateRedirectionURI(redirect *url.URL) error {
	if redirect.Scheme != "http" && redirect.Scheme != "https" {
		return errors.New("invalid uri scheme")
	}
	return nil
}
func ValidateRedirectionString(redirect string) (*url.URL, error) {
	u, err := url.Parse(redirect)
	if err != nil {
		return nil, err
	}
	return u, ValidateRedirectionURI(u)
}
