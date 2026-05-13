package config

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Postgres PostgresConfig `yaml:"postgres"`
	TOTP     TOTPConfig     `yaml:"totp"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	DSN            string `yaml:"dsn"`
	MigrationsPath string `yaml:"migrations_path"`
}

type TOTPConfig struct {
	Issuer string `yaml:"issuer"`
}
