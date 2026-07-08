package main

import (
	"os"

	"github.com/itsabgr/mauth"
	"gopkg.in/yaml.v3"
)

var config struct {
	Providers mauth.ProvidersConfig `yaml:"providers"`
}

func ParseConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}
