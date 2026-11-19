package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the application configuration.
type Config struct {
	Host                string `mapstructure:"host"`
	Port                int    `mapstructure:"port"`
	DSN                 string `mapstructure:"dsn"`
	HistoryLimit        int    `mapstructure:"history_limit"`
	StatsToken          string `mapstructure:"stats_token"`
	SecretEncryptionKey string `mapstructure:"secret_encryption_key"`
	TrustProxyHeaders   bool   `mapstructure:"trust_proxy_headers"`

	// File is the config file that was loaded, or empty if none was found.
	File string `mapstructure:"-"`
}

// Load reads configuration from file or environment variables.
//
// The config file is taken from FOONBLOB_CONFIG if set; otherwise config.toml is
// searched for in ".", "./config" and "/etc/foonblob-api". Environment variables
// prefixed with FOONBLOB_ override file values.
func Load() (*Config, error) {
	v := viper.New()

	// Default values
	v.SetDefault("host", "")
	v.SetDefault("port", 8080)
	v.SetDefault("dsn", "sync.db")
	v.SetDefault("history_limit", 10)
	v.SetDefault("stats_token", "")
	v.SetDefault("secret_encryption_key", "")
	v.SetDefault("trust_proxy_headers", true)

	// Environment variables
	v.SetEnvPrefix("FOONBLOB")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Config file
	if path := os.Getenv("FOONBLOB_CONFIG"); path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("toml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/foonblob-api")
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	cfg.File = v.ConfigFileUsed()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}
	if c.DSN == "" {
		return errors.New("dsn must not be empty")
	}
	if c.HistoryLimit < 1 {
		return fmt.Errorf("history_limit must be at least 1, got %d", c.HistoryLimit)
	}
	return nil
}
