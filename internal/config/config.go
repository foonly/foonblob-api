package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the application configuration.
type Config struct {
	Port                int    `mapstructure:"port"`
	DSN                 string `mapstructure:"dsn"`
	HistoryLimit        int    `mapstructure:"history_limit"`
	StatsToken          string `mapstructure:"stats_token"`
	SecretEncryptionKey string `mapstructure:"secret_encryption_key"`
}

// Load reads configuration from file or environment variables.
func Load() (*Config, error) {
	v := viper.New()

	// Default values
	v.SetDefault("port", 8080)
	v.SetDefault("dsn", "sync.db")
	v.SetDefault("history_limit", 10)
	v.SetDefault("stats_token", "")
	v.SetDefault("secret_encryption_key", "")

	// Environment variables
	v.SetEnvPrefix("FOONBLOB")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Config file
	v.SetConfigName("config")
	v.SetConfigType("toml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
