package config

import "time"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Postgres PostgresConfig `yaml:"postgres"`
	Redis    RedisConfig    `yaml:"redis"`
	HashSalt string         `yaml:"hash_salt"`
	IPRep    IPRepConfig    `yaml:"ip_reputation"`
	Trust    TrustConfig    `yaml:"trust"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type PostgresConfig struct {
	DSN            string `yaml:"dsn"`
	MigrationsPath string `yaml:"migrations_path"`
}

type RedisConfig struct {
	URL string `yaml:"url"`
}

type IPRepConfig struct {
	APIURL string `yaml:"api_url"`
	APIKey string `yaml:"api_key"`
}

type TrustConfig struct {
	Signals    SignalsConfig    `yaml:"signals"`
	Thresholds ThresholdsConfig `yaml:"thresholds"`
	Velocity   VelocityConfig   `yaml:"velocity"`
	IPScore    IPScoreConfig    `yaml:"ip_score"`
	GeoAnomaly GeoAnomalyConfig `yaml:"geo_anomaly"`
	AnonCheck  AnonCheckConfig  `yaml:"anon_check"`
}

type SignalsConfig struct {
	DeviceKnown  SignalConfig `yaml:"device_known"`
	IPReputation SignalConfig `yaml:"ip_reputation"`
	GeoAnomaly   SignalConfig `yaml:"geo_anomaly"`
	TimeOfDay    SignalConfig `yaml:"time_of_day"`
	Velocity     SignalConfig `yaml:"velocity"`
}

type SignalConfig struct {
	Weight float64 `yaml:"weight"`
}

type ThresholdsConfig struct {
	Allow       float64 `yaml:"allow"`
	MFARequired float64 `yaml:"mfa_required"`
	StepUp      float64 `yaml:"step_up"`
}

type VelocityConfig struct {
	FailTTL       time.Duration `yaml:"fail_ttl"`
	LowThreshold  int64         `yaml:"low_threshold"`
	HighThreshold int64         `yaml:"high_threshold"`
	LowScore      float64       `yaml:"low_score"`
	MidScore      float64       `yaml:"mid_score"`
	HighScore     float64       `yaml:"high_score"`
}

type IPScoreConfig struct {
	DatacenterScore  float64 `yaml:"datacenter_score"`
	TorScore         float64 `yaml:"tor_score"`
	ResidentialScore float64 `yaml:"residential_score"`
	UnknownScore     float64 `yaml:"unknown_score"`
}

type GeoAnomalyConfig struct {
	MaxSpeedKmh  float64 `yaml:"max_speed_kmh"`
	UnknownScore float64 `yaml:"unknown_score"`
}

type AnonCheckConfig struct {
	MaxIPFails int64         `yaml:"max_ip_fails"`
	IPFailTTL  time.Duration `yaml:"ip_fail_ttl"`
}
