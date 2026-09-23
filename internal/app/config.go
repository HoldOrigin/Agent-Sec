package app

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const Version = "0.5.0"

type Config struct {
	Host                string
	Port                int
	BodyLimit           int64
	FileCacheTTL        time.Duration
	CorrelationWindow   time.Duration
	InvestigationWindow time.Duration
	MaxAgentSteps       int
	QwenAPIKey          string
	PlannerModel        string
	ExecutorModel       string
	AnalyzerModel       string
	AgentAuditPath      string
	MaxAgentDecisions   int
	MaxAgentToolCalls   int
}

func LoadConfig() (Config, error) {
	port, err := envInt("PORT", 8080, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	body, err := envInt("BODY_LIMIT_BYTES", 1_000_000, 1024, 100_000_000)
	if err != nil {
		return Config{}, err
	}
	fileTTL, err := envInt("FILE_CACHE_TTL_SECONDS", 60, 1, 3600)
	if err != nil {
		return Config{}, err
	}
	correlation, err := envInt("CORRELATION_WINDOW_SECONDS", 300, 10, 3600)
	if err != nil {
		return Config{}, err
	}
	investigation, err := envInt("INVESTIGATION_WINDOW_SECONDS", 120, 10, 3600)
	if err != nil {
		return Config{}, err
	}
	steps, err := envInt("MAX_AGENT_STEPS", 10, 8, 20)
	if err != nil {
		return Config{}, err
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	decisions, err := envInt("AI_MAX_DECISIONS", 4, 1, 12)
	if err != nil {
		return Config{}, err
	}
	toolCalls, err := envInt("AI_MAX_TOOL_CALLS", 12, 1, 50)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Host: host, Port: port, BodyLimit: int64(body), FileCacheTTL: time.Duration(fileTTL) * time.Second,
		CorrelationWindow: time.Duration(correlation) * time.Second, InvestigationWindow: time.Duration(investigation) * time.Second,
		MaxAgentSteps: steps, QwenAPIKey: os.Getenv("QWEN_API_KEY"),
		PlannerModel:   envString("QWEN_PLANNER_MODEL", "qwen3.7-plus"),
		ExecutorModel:  envString("QWEN_EXECUTOR_MODEL", "qwen3.7-plus"),
		AnalyzerModel:  envString("QWEN_ANALYZER_MODEL", "qwen3.7-plus"),
		AgentAuditPath: os.Getenv("AI_AUDIT_LOG_PATH"), MaxAgentDecisions: decisions, MaxAgentToolCalls: toolCalls,
	}, nil
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func envInt(name string, fallback, min, max int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return value, nil
}
