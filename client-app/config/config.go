package config

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Gateway GatewayConfig `yaml:"gateway"`
	Client  ClientConfig  `yaml:"client"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
}

type GatewayConfig struct {
	URL       string `yaml:"url"`
	PublicURL string `yaml:"public_url"`
}

type ClientConfig struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}
