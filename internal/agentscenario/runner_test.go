package scenario

import (
	"context"
	"io"
	"testing"
)

func TestCatalogScenariosPassDeterministicFlow(t *testing.T) {
	for _, item := range Catalog() {
		t.Run(item.ID, func(t *testing.T) {
			outcome, err := Run(context.Background(), item, RunConfig{Mode: "deterministic", TraceWriter: io.Discard})
			if err != nil {
				t.Fatal(err)
			}
			if !outcome.Passed {
				t.Fatalf("scenario failed: %#v", outcome.Failures)
			}
		})
	}
}

func TestCatalogFixturesAreValid(t *testing.T) {
	seen := map[string]struct{}{}
	for _, item := range Catalog() {
		if _, exists := seen[item.ID]; exists {
			t.Fatalf("duplicate scenario %s", item.ID)
		}
		seen[item.ID] = struct{}{}
		if err := item.Validate(); err != nil {
			t.Fatalf("%s: %v", item.ID, err)
		}
	}
}
