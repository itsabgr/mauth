package mauth

import (
	"mauth/providers"
)

type ProvidersConfig map[string]struct {
	ClientId     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

func (pConf ProvidersConfig) InitProviders(providers map[string]providers.Provider, redirect string) error {
	for name := range providers {
		providersConfig, providersConfigExists := pConf[name]
		if !providersConfigExists {
			continue
		}
		providers[name].Enable(providersConfig.ClientId, providersConfig.ClientSecret, redirect)
	}
	return nil
}
