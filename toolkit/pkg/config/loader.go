package config

import (
	"fmt"
	"os"
	"regexp"

	"go.yaml.in/yaml/v2"
)

var envRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func Load(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	expanded := envRe.ReplaceAllFunc(data, func(b []byte) []byte {
		key := string(b[2 : len(b)-1])
		if v, ok := os.LookupEnv(key); ok {
			return []byte(v)
		}
		return b
	})
	if err := yaml.Unmarshal(expanded, out); err != nil {
		return fmt.Errorf("config: unmarshal: %w", err)
	}
	return nil
}

func Path() string {
	if p := os.Getenv("CONFIG_FILE"); p != "" {
		return p
	}
	return "config.yaml"
}
