package collector

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/google/cel-go/cel"
	"go.yaml.in/yaml/v3"
)

const (
	RuleKindBlacklist = "blacklist"
	RuleKindWhitelist = "whitelist"
	maxDetectionRules = 1000
	maxConditionBytes = 4096
	maxEvaluationCost = 10000
)

type DetectionRuleSpec struct {
	ID          string `yaml:"id" json:"id"`
	Kind        string `yaml:"kind" json:"kind"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Priority    int    `yaml:"priority,omitempty" json:"priority,omitempty"`
	Severity    string `yaml:"severity,omitempty" json:"severity,omitempty"`
	Condition   string `yaml:"condition" json:"condition"`
}

type DetectionRuleBundle struct {
	Version string              `yaml:"version" json:"version"`
	Rules   []DetectionRuleSpec `yaml:"rules" json:"rules"`
}

type compiledDetectionRule struct {
	spec    DetectionRuleSpec
	program cel.Program
}

type compiledDetectionSnapshot struct {
	version   string
	blacklist []compiledDetectionRule
	whitelist []compiledDetectionRule
}

type CELDetectionPolicy struct {
	snapshot atomic.Pointer[compiledDetectionSnapshot]
	fallback DetectionPolicy
	metrics  *Metrics
}

func NewCELDetectionPolicy(data []byte, fallback DetectionPolicy, metrics *Metrics) (*CELDetectionPolicy, error) {
	if fallback == nil {
		fallback = NewDefaultDetectionPolicy()
	}
	if metrics == nil {
		metrics = &Metrics{}
	}
	policy := &CELDetectionPolicy{fallback: fallback, metrics: metrics}
	if err := policy.Reload(data); err != nil {
		return nil, err
	}
	return policy, nil
}

func LoadCELDetectionPolicy(path string, fallback DetectionPolicy, metrics *Metrics) (*CELDetectionPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read detection rule bundle: %w", err)
	}
	return NewCELDetectionPolicy(data, fallback, metrics)
}

// Reload compiles a complete immutable snapshot before atomically publishing
// it. A malformed update never replaces the last valid rule set.
func (policy *CELDetectionPolicy) Reload(data []byte) error {
	snapshot, err := compileDetectionSnapshot(data)
	if err != nil {
		policy.metrics.RuleReloadErrors.Add(1)
		return err
	}
	policy.snapshot.Store(snapshot)
	policy.metrics.RuleReloads.Add(1)
	return nil
}

func (policy *CELDetectionPolicy) ReloadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		policy.metrics.RuleReloadErrors.Add(1)
		return fmt.Errorf("read detection rule bundle: %w", err)
	}
	return policy.Reload(data)
}

func (policy *CELDetectionPolicy) Evaluate(event map[string]any) DetectionDecision {
	snapshot := policy.snapshot.Load()
	if snapshot != nil {
		if decision, matched := policy.evaluateRules(snapshot.blacklist, event, true); matched {
			policy.metrics.BlacklistHits.Add(1)
			return decision
		}
		if decision, matched := policy.evaluateRules(snapshot.whitelist, event, false); matched {
			policy.metrics.WhitelistHits.Add(1)
			return decision
		}
	}
	return policy.fallback.Evaluate(event)
}

func (policy *CELDetectionPolicy) Version() string {
	if snapshot := policy.snapshot.Load(); snapshot != nil {
		return snapshot.version
	}
	return ""
}

func (policy *CELDetectionPolicy) evaluateRules(rules []compiledDetectionRule, event map[string]any, blacklist bool) (DetectionDecision, bool) {
	for _, rule := range rules {
		output, _, err := rule.program.Eval(map[string]any{"event": event})
		if err != nil {
			policy.metrics.RuleEvaluationErrors.Add(1)
			continue
		}
		matched, ok := output.Value().(bool)
		if !ok {
			policy.metrics.RuleEvaluationErrors.Add(1)
			continue
		}
		if !matched {
			continue
		}
		if blacklist {
			return DetectionDecision{Alert: true, Blacklist: true, RuleID: rule.spec.ID, Severity: firstString(rule.spec.Severity, "high"), Reason: firstString(rule.spec.Description, "CEL blacklist rule matched")}, true
		}
		return DetectionDecision{Whitelist: true, RuleID: rule.spec.ID, Reason: firstString(rule.spec.Description, "CEL whitelist rule matched")}, true
	}
	return DetectionDecision{}, false
}

func compileDetectionSnapshot(data []byte) (*compiledDetectionSnapshot, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var bundle DetectionRuleBundle
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decode detection rule bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("detection rule bundle must contain one YAML document")
	}
	if strings.TrimSpace(bundle.Version) == "" {
		return nil, errors.New("detection rule bundle version is required")
	}
	if len(bundle.Rules) > maxDetectionRules {
		return nil, fmt.Errorf("detection rule count %d exceeds limit %d", len(bundle.Rules), maxDetectionRules)
	}
	environment, err := cel.NewEnv(cel.Variable("event", cel.DynType))
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	snapshot := &compiledDetectionSnapshot{version: bundle.Version}
	seen := map[string]bool{}
	for index, rule := range bundle.Rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Kind = strings.ToLower(strings.TrimSpace(rule.Kind))
		rule.Condition = strings.TrimSpace(rule.Condition)
		if rule.ID == "" {
			return nil, fmt.Errorf("rule %d: id is required", index)
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("rule %q: duplicate id", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Kind != RuleKindBlacklist && rule.Kind != RuleKindWhitelist {
			return nil, fmt.Errorf("rule %q: kind must be blacklist or whitelist", rule.ID)
		}
		if rule.Condition == "" || len(rule.Condition) > maxConditionBytes {
			return nil, fmt.Errorf("rule %q: condition length must be between 1 and %d bytes", rule.ID, maxConditionBytes)
		}
		ast, issues := environment.Compile(rule.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %q: compile CEL: %w", rule.ID, issues.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("rule %q: CEL condition must return bool, got %s", rule.ID, ast.OutputType())
		}
		program, err := environment.Program(ast, cel.CostLimit(maxEvaluationCost), cel.InterruptCheckFrequency(100))
		if err != nil {
			return nil, fmt.Errorf("rule %q: build CEL program: %w", rule.ID, err)
		}
		compiled := compiledDetectionRule{spec: rule, program: program}
		if rule.Kind == RuleKindBlacklist {
			snapshot.blacklist = append(snapshot.blacklist, compiled)
		} else {
			snapshot.whitelist = append(snapshot.whitelist, compiled)
		}
	}
	sortRules := func(rules []compiledDetectionRule) {
		sort.SliceStable(rules, func(left, right int) bool {
			if rules[left].spec.Priority == rules[right].spec.Priority {
				return rules[left].spec.ID < rules[right].spec.ID
			}
			return rules[left].spec.Priority > rules[right].spec.Priority
		})
	}
	sortRules(snapshot.blacklist)
	sortRules(snapshot.whitelist)
	return snapshot, nil
}
