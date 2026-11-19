package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Chdir(t.TempDir())

	t.Run("Defaults", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Port != 8080 || cfg.HistoryLimit != 10 || !cfg.TrustProxyHeaders || cfg.File != "" {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
	})

	t.Run("EnvOverridesFile", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "c.toml")
		os.WriteFile(path, []byte("port = 9000\nhost = \"127.0.0.1\"\n"), 0o600)
		t.Setenv("FOONBLOB_CONFIG", path)
		t.Setenv("FOONBLOB_PORT", "9001")
		t.Setenv("FOONBLOB_TRUST_PROXY_HEADERS", "false")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Port != 9001 || cfg.Host != "127.0.0.1" || cfg.TrustProxyHeaders || cfg.File != path {
			t.Fatalf("unexpected config: %+v", cfg)
		}
	})

	t.Run("MissingExplicitFileFails", func(t *testing.T) {
		t.Setenv("FOONBLOB_CONFIG", "/nonexistent/config.toml")
		if _, err := Load(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("InvalidHistoryLimit", func(t *testing.T) {
		t.Setenv("FOONBLOB_HISTORY_LIMIT", "0")
		if _, err := Load(); err == nil {
			t.Fatal("expected error")
		}
	})
}
