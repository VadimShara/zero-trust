package config

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Redis    RedisConfig    `yaml:"redis"`
	Keycloak KeycloakConfig `yaml:"keycloak"`
	Services ServicesConfig `yaml:"services"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type RedisConfig struct {
	URL string `yaml:"url"`
}

type KeycloakConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	PublicURL    string `yaml:"public_url"`
	CallbackURL  string `yaml:"callback_url"`
}

type ServicesConfig struct {
	GatewayPrivate string `yaml:"gateway_private"`
	GatewayPublic  string `yaml:"gateway_public"`
	Auth           string `yaml:"auth"`
}
