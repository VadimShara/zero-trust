package config

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Redis    RedisConfig    `yaml:"redis"`
	Client   ClientConfig   `yaml:"client"`
	Public   PublicConfig   `yaml:"public"`
	Services ServicesConfig `yaml:"services"`
}

type ServerConfig struct {
	PublicAddr  string `yaml:"public_addr"`
	PrivateAddr string `yaml:"private_addr"`
}

type RedisConfig struct {
	URL string `yaml:"url"`
}

type ClientConfig struct {
	ID          string `yaml:"id"`
	Secret      string `yaml:"secret"`
	CallbackURL string `yaml:"callback_url"`
}

type PublicConfig struct {
	GatewayURL string `yaml:"gateway_url"`
}

type ServicesConfig struct {
	Trust      string `yaml:"trust"`
	Token      string `yaml:"token"`
	IDPAdapter string `yaml:"idpadapter"`
	OPA        string `yaml:"opa"`
	Auth       string `yaml:"auth"`
	Audit      string `yaml:"audit"`
}
