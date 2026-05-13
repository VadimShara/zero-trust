package config

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Postgres PostgresConfig `yaml:"postgres"`
	Kafka    KafkaConfig    `yaml:"kafka"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	DSN            string `yaml:"dsn"`
	MigrationsPath string `yaml:"migrations_path"`
}

type KafkaConfig struct {
	Brokers []string `yaml:"brokers"`
	GroupID string   `yaml:"group_id"`
	Topics  []string `yaml:"topics"`
}
