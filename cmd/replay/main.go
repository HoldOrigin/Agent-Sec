package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	file := flag.String("file", "datasets/web_rce.jsonl", "JSONL input file")
	base := flag.String("url", "http://127.0.0.1:8080", "server URL")
	reset := flag.Bool("reset", false, "reset server state first")
	interval := flag.Duration("interval", 50*time.Millisecond, "delay between events")
	flag.Parse()
	if *reset {
		if _, err := call(*base, "/api/reset", map[string]any{}); err != nil {
			log.Fatal(err)
		}
	}
	handle, err := os.Open(*file)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	scanner := bufio.NewScanner(handle)
	events := []map[string]any{}
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			log.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Replaying %d events from %s\n", len(events), *file)
	for index, event := range events {
		payload, err := call(*base, "/api/events", event)
		if err != nil {
			log.Fatal(err)
		}
		var result struct {
			Behaviors []any `json:"behaviors"`
			Incidents []any `json:"incidents"`
		}
		if err := json.Unmarshal(payload, &result); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[%d/%d] %v %v → %d behaviors, %d incidents\n", index+1, len(events), event["event_id"], event["type"], len(result.Behaviors), len(result.Incidents))
		if index < len(events)-1 && *interval > 0 {
			time.Sleep(*interval)
		}
	}
	summary, err := get(*base, "/api/summary")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Done: %s\n", strings.TrimSpace(string(summary)))
}
func call(base, path string, body any) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	response, err := http.Post(strings.TrimRight(base, "/")+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: %s", path, payload)
	}
	return payload, nil
}
func get(base, path string) ([]byte, error) {
	response, err := http.Get(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}
