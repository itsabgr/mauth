package mauth

import (
	"aidanwoods.dev/go-paseto"
	"time"
)

type State struct {
	RedirectURI string `msgpack:"R"`
	Provider    string `msgpack:"P"`
}

func (s *State) Encrypt(key paseto.V4SymmetricKey) string {
	tkn := paseto.NewToken()
	tkn.SetString("r", s.RedirectURI)
	tkn.SetString("p", s.Provider)
	tkn.SetExpiration(time.Now().Add(time.Minute * 10))
	return tkn.V4Encrypt(key, nil)
}

func (s *State) Decrypt(b string, key paseto.V4SymmetricKey) error {
	tkn, err := paseto.NewParser().ParseV4Local(key, b, nil)
	if err != nil {
		return err
	}
	redirectURI, err := tkn.GetString("r")
	if err != nil {
		return err
	}
	provider, err := tkn.GetString("p")
	if err != nil {
		return err
	}
	s.RedirectURI = redirectURI
	s.Provider = provider
	return nil
}
