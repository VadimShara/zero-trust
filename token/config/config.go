package config

import "time"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Redis    RedisConfig    `yaml:"redis"`
	Kafka    KafkaConfig    `yaml:"kafka"`
	Services ServicesConfig `yaml:"services"`
	Tokens   TokensConfig   `yaml:"tokens"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type RedisConfig struct {
	URL string `yaml:"url"`
}

type KafkaConfig struct {
	Brokers []string `yaml:"brokers"`
}

type ServicesConfig struct {
	Trust string `yaml:"trust"`
}

type TokensConfig struct {
	AccessTTL  time.Duration `yaml:"access_ttl"`
	RefreshTTL time.Duration `yaml:"refresh_ttl"`
}
