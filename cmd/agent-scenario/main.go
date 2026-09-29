package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentinel/internal/agentscenario"
)

func main() {
	var selected, mode, auditPath string
	var list, quiet bool
	var timeout time.Duration
	flag.StringVar(&selected, "scenario", "all", "scenario ID or all")
	flag.StringVar(&mode, "mode", "deterministic", "deterministic or qwen")
	flag.StringVar(&auditPath, "audit", "", "optional JSONL audit output path")
	flag.BoolVar(&list, "list", false, "list built-in scenarios")
	flag.BoolVar(&quiet, "quiet", false, "print only scenario summaries")
	flag.DurationVar(&timeout, "timeout", 2*time.Minute, "timeout for each scenario")
	flag.Parse()

	catalog := scenario.Catalog()
	if list {
		for _, item := range catalog {
			fmt.Printf("%-26s %s\n", item.ID, item.Name)
		}
		return
	}
	items, err := selectScenarios(catalog, selected)
	if err != nil {
		fatal(err)
	}
	writers := []io.Writer{}
	if !quiet {
		writers = append(writers, os.Stdout)
	}
	var auditFile *os.File
	if auditPath != "" {
		if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil && filepath.Dir(auditPath) != "." {
			fatal(err)
		}
		auditFile, err = os.OpenFile(auditPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			fatal(err)
		}
		defer auditFile.Close()
		writers = append(writers, auditFile)
	}
	var trace io.Writer
	if len(writers) > 0 {
		trace = io.MultiWriter(writers...)
	}

	failed := 0
	for _, item := range items {
		fmt.Printf("\n=== SCENARIO START id=%s name=%s mode=%s ===\n", item.ID, item.Name, mode)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		outcome, runErr := scenario.Run(ctx, item, scenario.RunConfig{Mode: mode, APIKey: os.Getenv("QWEN_API_KEY"), PlannerModel: env("QWEN_PLANNER_MODEL", "qwen3.7-plus"), ExecutorModel: env("QWEN_EXECUTOR_MODEL", "qwen3.7-plus"), AnalyzerModel: env("QWEN_ANALYZER_MODEL", "qwen3.7-plus"), TraceWriter: trace})
		cancel()
		if runErr != nil {
			failed++
			fmt.Printf("=== SCENARIO FAIL id=%s error=%q ===\n", item.ID, runErr)
			continue
		}
		summary, _ := json.Marshal(map[string]any{"scenario": item.ID, "passed": outcome.Passed, "run_status": outcome.Result.Status, "classification": outcome.Result.Report.Classification, "tasks": len(outcome.Result.Tasks), "evidence": len(outcome.Result.Evidence), "failures": outcome.Failures})
		fmt.Println(string(summary))
		if !outcome.Passed {
			failed++
			fmt.Printf("=== SCENARIO FAIL id=%s ===\n", item.ID)
		} else {
			fmt.Printf("=== SCENARIO PASS id=%s ===\n", item.ID)
		}
	}
	fmt.Printf("\n=== SUITE END total=%d passed=%d failed=%d ===\n", len(items), len(items)-failed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func selectScenarios(catalog []scenario.Scenario, selected string) ([]scenario.Scenario, error) {
	if selected == "all" {
		return catalog, nil
	}
	requested := map[string]struct{}{}
	for _, id := range strings.Split(selected, ",") {
		requested[strings.TrimSpace(id)] = struct{}{}
	}
	result := []scenario.Scenario{}
	for _, item := range catalog {
		if _, ok := requested[item.ID]; ok {
			result = append(result, item)
			delete(requested, item.ID)
		}
	}
	if len(requested) > 0 {
		unknown := make([]string, 0, len(requested))
		for id := range requested {
			unknown = append(unknown, id)
		}
		return nil, fmt.Errorf("unknown scenarios: %s", strings.Join(unknown, ", "))
	}
	return result, nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "agent-scenario:", err)
	os.Exit(1)
}
