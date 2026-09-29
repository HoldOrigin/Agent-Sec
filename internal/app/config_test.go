package app

import (
	"strings"
	"testing"
)

func TestLoadConfigRequiresPostgreSQLByDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("ALLOW_IN_MEMORY_STORAGE", "")
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL is required") {
		t.Fatalf("error=%v, want DATABASE_URL requirement", err)
	}
}

func TestLoadConfigAllowsExplicitDevelopmentMemoryMode(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("ALLOW_IN_MEMORY_STORAGE", "true")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.AllowInMemoryStore {
		t.Fatal("memory mode was not enabled")
	}
}

func TestLoadConfigAcceptsPostgreSQL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://sentinel:secret@127.0.0.1:5432/sentinel")
	t.Setenv("ALLOW_IN_MEMORY_STORAGE", "")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.DatabaseURL == "" || config.AllowInMemoryStore {
		t.Fatalf("config=%+v", config)
	}
}
