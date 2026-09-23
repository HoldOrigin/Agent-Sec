package investigation

import (
	"fmt"
	"regexp"
)

type Plan struct {
	Hypotheses []string `json:"hypotheses"`
	Tasks      []Task   `json:"tasks"`
}

type Task struct {
	ID            string   `json:"task_id"`
	Question      string   `json:"question"`
	DependsOn     []string `json:"depends_on"`
	RequiredTools []string `json:"required_tools"`
	OptionalTools []string `json:"optional_tools"`
}

type ActionKind string

const (
	ActionCallTool      ActionKind = "CALL_TOOL"
	ActionFinish        ActionKind = "FINISH"
	ActionRequestReplan ActionKind = "REQUEST_REPLAN"
)

type Action struct {
	Action       ActionKind     `json:"action"`
	Purpose      string         `json:"purpose,omitempty"`
	Tool         string         `json:"tool,omitempty"`
	Arguments    map[string]any `json:"arguments,omitempty"`
	Findings     []Finding      `json:"findings,omitempty"`
	Gaps         []string       `json:"gaps,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	EvidenceRefs []string       `json:"evidence_refs,omitempty"`
}

type Finding struct {
	Statement   string   `json:"statement"`
	Type        string   `json:"type"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type TaskResult struct {
	TaskID       string           `json:"task_id"`
	Status       string           `json:"status"`
	Findings     []Finding        `json:"findings"`
	Gaps         []string         `json:"gaps"`
	Observations []map[string]any `json:"observations"`
	EvidenceRefs []string         `json:"evidence_refs"`
}

type Report struct {
	Classification  string    `json:"classification"`
	Summary         string    `json:"summary"`
	Findings        []Finding `json:"findings"`
	MissingEvidence []string  `json:"missing_evidence"`
	Recommendations []string  `json:"recommendations"`
}

func ValidatePlan(plan Plan, available map[string]struct{}) error {
	if len(plan.Hypotheses) == 0 || len(plan.Hypotheses) > 8 || len(plan.Tasks) == 0 || len(plan.Tasks) > 8 {
		return fmt.Errorf("plan size is invalid")
	}
	ids := map[string]struct{}{}
	for _, task := range plan.Tasks {
		if !regexp.MustCompile(`^T[1-9][0-9]?$`).MatchString(task.ID) {
			return fmt.Errorf("invalid task id %s", task.ID)
		}
		if _, exists := ids[task.ID]; exists {
			return fmt.Errorf("duplicate task id %s", task.ID)
		}
		ids[task.ID] = struct{}{}
		if task.Question == "" || len(task.Question) > 500 {
			return fmt.Errorf("invalid task question")
		}
		tools := append(append([]string(nil), task.RequiredTools...), task.OptionalTools...)
		if len(task.RequiredTools) == 0 || len(tools) > 5 {
			return fmt.Errorf("task %s tool assignment is invalid", task.ID)
		}
		seen := map[string]struct{}{}
		for _, name := range tools {
			if _, ok := available[name]; !ok {
				return fmt.Errorf("task %s uses unavailable tool %s", task.ID, name)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("task %s repeats tool %s", task.ID, name)
			}
			seen[name] = struct{}{}
		}
	}
	resolved := map[string]struct{}{}
	for len(resolved) < len(plan.Tasks) {
		progress := false
		for _, task := range plan.Tasks {
			if _, done := resolved[task.ID]; done {
				continue
			}
			ready := true
			for _, dependency := range task.DependsOn {
				if _, exists := ids[dependency]; !exists {
					return fmt.Errorf("unknown dependency %s", dependency)
				}
				if _, done := resolved[dependency]; !done {
					ready = false
				}
			}
			if ready {
				resolved[task.ID] = struct{}{}
				progress = true
			}
		}
		if !progress {
			return fmt.Errorf("task dependency cycle")
		}
	}
	return nil
}

func ValidateAction(action Action, task Task, active map[string]struct{}) error {
	switch action.Action {
	case ActionCallTool:
		if action.Purpose == "" || len(action.Purpose) > 500 || action.Tool == "" || action.Arguments == nil {
			return fmt.Errorf("invalid tool action")
		}
		if _, ok := active[action.Tool]; !ok {
			return fmt.Errorf("tool is not active")
		}
	case ActionFinish:
		for _, finding := range action.Findings {
			if finding.Statement == "" || len(finding.Statement) > 2000 || (finding.Type != "OBSERVED" && finding.Type != "INFERRED" && finding.Type != "UNKNOWN") {
				return fmt.Errorf("invalid finding")
			}
			if finding.Type != "UNKNOWN" && len(finding.EvidenceIDs) == 0 {
				return fmt.Errorf("finding requires evidence")
			}
		}
	case ActionRequestReplan:
		if action.Reason == "" || len(action.EvidenceRefs) == 0 {
			return fmt.Errorf("replan requires reason and evidence")
		}
	default:
		return fmt.Errorf("unknown action")
	}
	return nil
}
